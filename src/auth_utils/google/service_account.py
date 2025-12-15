"""Google Service Account authentication.

Service accounts are used for server-to-server authentication without user interaction.
The service account acts as its own identity and can access:
- Resources explicitly shared with the service account email
- Google Workspace resources (if domain-wide delegation is configured)
- Public Google APIs

Example:
    >>> auth = GoogleServiceAccount(
    ...     key_path="service_account_key.json",
    ...     scopes=["docs", "drive"]
    ... )
    >>> docs_service = auth.build_service("docs", "v1")
"""

import json
import logging
from pathlib import Path

from google.oauth2 import service_account
from googleapiclient.discovery import build

from auth_utils.google.exceptions import CredentialsNotFoundError, GoogleAuthError
from auth_utils.google.oauth import SCOPES

logger = logging.getLogger(__name__)


class GoogleServiceAccount:
    """Google Service Account authentication.

    Uses a service account key file for server-to-server authentication.
    No user interaction required.

    Note: To access user data (Docs, Drive, etc.), the user must share
    those resources with the service account email address.
    """

    def __init__(
        self,
        key_path: str | Path = "service_account_key.json",
        scopes: list[str] | None = None,
    ):
        """Initialize service account authentication.

        Args:
            key_path: Path to service account JSON key file.
            scopes: List of scope names (e.g., ["docs", "drive"]) or full URLs.
                   If None, defaults to ["docs", "drive"].

        Raises:
            CredentialsNotFoundError: If key file not found.
            GoogleAuthError: If key file is invalid.
        """
        self.key_path = Path(key_path)

        if not self.key_path.exists():
            raise CredentialsNotFoundError(str(self.key_path))

        # Resolve scope names to full URLs
        self.scopes = self._resolve_scopes(scopes or ["docs", "drive"])

        # Load and validate the key file
        try:
            with open(self.key_path) as f:
                key_data = json.load(f)

            if key_data.get("type") != "service_account":
                raise GoogleAuthError(
                    f"Invalid key file: expected type 'service_account', "
                    f"got '{key_data.get('type')}'"
                )

            self.client_email = key_data.get("client_email", "")
            self.project_id = key_data.get("project_id", "")

        except json.JSONDecodeError as e:
            raise GoogleAuthError(f"Invalid JSON in key file: {e}") from e

        # Create credentials
        self._credentials = service_account.Credentials.from_service_account_file(
            str(self.key_path),
            scopes=self.scopes,
        )

        logger.info(f"Service account initialized: {self.client_email}")
        logger.info(f"Scopes: {self.scopes}")

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

    @property
    def credentials(self):
        """Get the service account credentials."""
        return self._credentials

    @property
    def email(self) -> str:
        """Get the service account email address.

        Share your Google resources with this email to grant access.
        """
        return self.client_email

    def build_service(self, service_name: str = "docs", version: str = "v1"):
        """Build a Google API service with service account credentials.

        Args:
            service_name: Name of the service (e.g., 'docs', 'drive', 'sheets').
            version: API version (e.g., 'v1', 'v3').

        Returns:
            Google API service object.
        """
        return build(service_name, version, credentials=self._credentials)

    def with_subject(self, subject_email: str) -> "GoogleServiceAccount":
        """Create credentials that impersonate a user (requires domain-wide delegation).

        This is only available for Google Workspace domains where the service
        account has been granted domain-wide delegation.

        Args:
            subject_email: Email of the user to impersonate.

        Returns:
            New GoogleServiceAccount instance with delegated credentials.
        """
        delegated_credentials = self._credentials.with_subject(subject_email)

        # Create a new instance with the delegated credentials
        new_instance = object.__new__(GoogleServiceAccount)
        new_instance.key_path = self.key_path
        new_instance.scopes = self.scopes
        new_instance.client_email = self.client_email
        new_instance.project_id = self.project_id
        new_instance._credentials = delegated_credentials

        logger.info(f"Created delegated credentials for: {subject_email}")
        return new_instance

    def get_info(self) -> dict:
        """Get information about the service account.

        Returns:
            Dictionary with service account details.
        """
        return {
            "type": "service_account",
            "email": self.client_email,
            "project_id": self.project_id,
            "scopes": self.scopes,
            "key_path": str(self.key_path),
        }
