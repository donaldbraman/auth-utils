"""Google OAuth management using Authlib.

This module provides OAuth 2.0 authentication for Google APIs with:
- Automatic token refresh with scope preservation
- Secure token storage and loading
- Google API service creation (Docs, Drive, etc.)

Credentials are stored centrally in the auth-utils repo by default:
    google/credentials.json - OAuth client credentials
    google/token.json       - OAuth tokens
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2 import OAuth2Error
from google.oauth2.credentials import Credentials as GoogleCredentials
from googleapiclient.discovery import build

from auth_utils.config import GOOGLE_CREDENTIALS, GOOGLE_TOKEN
from auth_utils.google.exceptions import (
    CredentialsNotFoundError,
    ScopeMismatchError,
    TokenError,
)

logger = logging.getLogger(__name__)


# Common Google OAuth scopes
SCOPES = {
    "docs": "https://www.googleapis.com/auth/documents",
    "docs_readonly": "https://www.googleapis.com/auth/documents.readonly",
    "drive": "https://www.googleapis.com/auth/drive",
    "drive_readonly": "https://www.googleapis.com/auth/drive.readonly",
    "drive_file": "https://www.googleapis.com/auth/drive.file",
    "sheets": "https://www.googleapis.com/auth/spreadsheets",
    "sheets_readonly": "https://www.googleapis.com/auth/spreadsheets.readonly",
    "gmail": "https://www.googleapis.com/auth/gmail.modify",
    "gmail_readonly": "https://www.googleapis.com/auth/gmail.readonly",
    "calendar": "https://www.googleapis.com/auth/calendar",
    "calendar_readonly": "https://www.googleapis.com/auth/calendar.readonly",
}


class GoogleOAuth:
    """Google OAuth management using Authlib.

    Handles OAuth 2.0 authorization flow, token management, and
    Google API service creation.

    Example:
        >>> auth = GoogleOAuth(scopes=["docs", "drive"])
        >>> if not auth.is_authorized():
        ...     url = auth.get_authorization_url()
        ...     print(f"Visit: {url}")
        ...     redirect_url = input("Paste redirect URL: ")
        ...     auth.fetch_token(redirect_url)
        >>> docs_service = auth.build_service("docs", "v1")
    """

    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"

    def __init__(
        self,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_path: str | Path | None = None,
        credentials_path: str | Path | None = None,
    ):
        """Initialize Google OAuth.

        Args:
            scopes: List of scope names (e.g., ["docs", "drive"]) or full URLs.
                   If None, defaults to ["docs", "drive"].
            client_id: OAuth client ID (loaded from credentials file if not provided).
            client_secret: OAuth client secret (loaded from credentials file if not provided).
            token_path: Path to store/load tokens. Defaults to auth-utils/google/token.json.
            credentials_path: Path to OAuth credentials file. Defaults to auth-utils/google/credentials.json.
        """
        self.token_path = Path(token_path) if token_path else GOOGLE_TOKEN
        self.credentials_path = Path(credentials_path) if credentials_path else GOOGLE_CREDENTIALS

        # Resolve scope names to full URLs
        self.required_scopes = self._resolve_scopes(scopes or ["docs", "drive"])

        # Load client credentials
        if not client_id or not client_secret:
            client_id, client_secret = self._load_client_credentials()

        self.client_id = client_id
        self.client_secret = client_secret

        # Initialize OAuth2Session
        self.session = OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=" ".join(self.required_scopes),
            redirect_uri="http://localhost:0",
            token=self._load_token(),
            update_token=self._save_token,
            token_endpoint=self.TOKEN_URL,
            grant_type="refresh_token",
            token_endpoint_auth_method="client_secret_post",
        )

        self._state: str | None = None
        self.last_refresh: datetime | None = None
        self.refresh_count = 0

    def _resolve_scopes(self, scopes: list[str]) -> list[str]:
        """Resolve scope names to full URLs."""
        resolved = []
        for scope in scopes:
            if scope.startswith("https://"):
                resolved.append(scope)
            elif scope in SCOPES:
                resolved.append(SCOPES[scope])
            else:
                raise ValueError(
                    f"Unknown scope: {scope}. Use full URL or one of: {list(SCOPES.keys())}"
                )
        return resolved

    def _load_client_credentials(self) -> tuple[str, str]:
        """Load OAuth client credentials from file."""
        if not self.credentials_path.exists():
            raise CredentialsNotFoundError(str(self.credentials_path))

        with open(self.credentials_path) as f:
            creds = json.load(f)

        # Handle both web and installed app credential formats
        if "installed" in creds:
            app_creds = creds["installed"]
        elif "web" in creds:
            app_creds = creds["web"]
        else:
            raise ValueError("Invalid credentials.json format. Expected 'installed' or 'web' key.")

        return app_creds["client_id"], app_creds["client_secret"]

    def _load_token(self) -> dict[str, Any] | None:
        """Load token from storage."""
        if not self.token_path.exists():
            logger.info("No existing token found")
            return None

        try:
            with open(self.token_path) as f:
                token_data = json.load(f)

            # Convert expiry to timestamp if in ISO format
            expiry = token_data.get("expiry")
            if expiry and isinstance(expiry, str):
                dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                expires_at = dt.timestamp()
            else:
                expires_at = expiry

            # Convert Google token format to Authlib format
            authlib_token = {
                "access_token": token_data.get("token"),
                "refresh_token": token_data.get("refresh_token"),
                "token_type": token_data.get("type", "Bearer"),
                "expires_at": expires_at,
                "scope": " ".join(token_data.get("scopes", [])),
            }

            # Validate scopes
            current_scopes = set(token_data.get("scopes", []))
            required_scopes = set(self.required_scopes)

            if not required_scopes.issubset(current_scopes):
                missing = required_scopes - current_scopes
                logger.warning(f"Token missing required scopes: {missing}")
                return None

            logger.info(f"Loaded token with scopes: {current_scopes}")
            return authlib_token

        except Exception as e:
            logger.error(f"Failed to load token: {e}")
            return None

    def _save_token(
        self,
        token: dict[str, Any],
        refresh_token: str | None = None,
        access_token: str | None = None,
    ):
        """Save token to storage (Authlib callback)."""
        if access_token:
            token["access_token"] = access_token
        if refresh_token:
            token["refresh_token"] = refresh_token

        # Validate scopes
        token_scopes = set(token.get("scope", "").split())
        required_scopes = set(self.required_scopes)

        if not required_scopes.issubset(token_scopes):
            missing = required_scopes - token_scopes
            raise ScopeMismatchError(missing)

        # Convert to Google token format for compatibility
        google_token = {
            "token": token["access_token"],
            "refresh_token": token.get("refresh_token"),
            "token_uri": self.TOKEN_URL,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scopes": list(token_scopes),
            "type": token.get("token_type", "Bearer"),
            "expiry": token.get("expires_at"),
            "_class": "google.oauth2.credentials.Credentials",
        }

        with open(self.token_path, "w") as f:
            json.dump(google_token, f, indent=2)

        self.last_refresh = datetime.now()
        self.refresh_count += 1

        logger.info(f"Token saved with scopes: {token_scopes}")

    def is_authorized(self) -> bool:
        """Check if we have valid authorization with required scopes.

        Returns:
            True if authorized with all required scopes, False otherwise.
        """
        if not self.session.token:
            return False

        # Verify scopes
        token_scopes = set(self.session.token.get("scope", "").split())
        required_scopes = set(self.required_scopes)

        return required_scopes.issubset(token_scopes)

    def get_authorization_url(self) -> str:
        """Start OAuth authorization flow.

        Returns:
            Authorization URL for user to visit.
        """
        authorization_url, state = self.session.create_authorization_url(
            self.AUTHORIZE_URL,
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true",
        )

        self._state = state
        return authorization_url

    def fetch_token(self, authorization_response: str) -> dict[str, Any]:
        """Complete authorization flow and fetch token.

        Args:
            authorization_response: The full redirect URL from OAuth callback.

        Returns:
            The fetched OAuth token dict.
        """
        token = self.session.fetch_token(
            self.TOKEN_URL,
            authorization_response=authorization_response,
            client_secret=self.client_secret,
        )

        self._save_token(token)
        return token

    def get_credentials(self) -> GoogleCredentials:
        """Get Google Credentials object for API client libraries.

        Returns:
            Google Credentials object with current token.

        Raises:
            TokenError: If not authorized or token refresh fails.
        """
        if not self.is_authorized():
            raise TokenError("Not authorized or missing required scopes")

        # Refresh if expired
        expires_at = self.session.token.get("expires_at", 0)
        if expires_at and expires_at < datetime.now().timestamp():
            logger.info("Token expired, refreshing...")
            try:
                self.session.refresh_token(
                    self.TOKEN_URL,
                    refresh_token=self.session.token.get("refresh_token"),
                )
            except OAuth2Error as e:
                raise TokenError(f"Failed to refresh token: {e}") from e

        return GoogleCredentials(
            token=self.session.token["access_token"],
            refresh_token=self.session.token.get("refresh_token"),
            token_uri=self.TOKEN_URL,
            client_id=self.client_id,
            client_secret=self.client_secret,
            scopes=self.required_scopes,
        )

    def build_service(self, service_name: str = "docs", version: str = "v1"):
        """Build a Google API service with current credentials.

        Args:
            service_name: Name of the service (e.g., 'docs', 'drive', 'sheets').
            version: API version (e.g., 'v1').

        Returns:
            Google API service object.
        """
        creds = self.get_credentials()
        return build(service_name, version, credentials=creds)

    def revoke_token(self):
        """Revoke the current token and clear local storage."""
        if not self.session.token:
            logger.warning("No token to revoke")
            return

        try:
            self.session.post(
                self.REVOKE_URL,
                params={"token": self.session.token["access_token"]},
            )
        except Exception as e:
            logger.warning(f"Failed to revoke token remotely: {e}")

        if self.token_path.exists():
            self.token_path.unlink()

        logger.info("Token revoked successfully")

    def get_token_info(self) -> dict[str, Any]:
        """Get information about the current token.

        Returns:
            Dictionary with token status, scopes, expiry, etc.
        """
        if not self.session.token:
            return {"status": "no_token"}

        token = self.session.token
        expires_at = token.get("expires_at", 0)

        if expires_at:
            expires_in = expires_at - datetime.now().timestamp()
            expires_str = str(timedelta(seconds=max(0, expires_in)))
            is_expired = expires_at < datetime.now().timestamp()
        else:
            expires_str = "unknown"
            is_expired = False

        return {
            "status": "valid" if not is_expired else "expired",
            "scopes": token.get("scope", "").split(),
            "expires_in": expires_str,
            "has_refresh_token": bool(token.get("refresh_token")),
            "refresh_count": self.refresh_count,
            "last_refresh": self.last_refresh.isoformat() if self.last_refresh else None,
        }
