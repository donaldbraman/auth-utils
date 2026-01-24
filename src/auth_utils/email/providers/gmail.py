"""Gmail SMTP provider with macOS Keychain support."""

from __future__ import annotations

import os
import subprocess
import sys

from auth_utils.email.exceptions import SMTPAuthError
from auth_utils.email.providers.base import BaseSMTPProvider

# Keychain configuration
KEYCHAIN_SERVICE = "auth-utils-gmail"


class GmailProvider(BaseSMTPProvider):
    """Gmail SMTP provider (smtp.gmail.com:587).

    Credentials are loaded in priority order:
    1. Explicit user/password passed to constructor
    2. macOS Keychain (service: auth-utils-gmail)
    3. Environment variables (GMAIL_SMTP_USER, GMAIL_SMTP_PASSWORD)

    Usage:
        # Auto-detect credentials
        provider = GmailProvider()

        # Explicit credentials
        provider = GmailProvider(user="me@gmail.com", password="app-password")

        # Explicit user, password from Keychain/env
        provider = GmailProvider(user="me@gmail.com")
    """

    def __init__(
        self,
        user: str | None = None,
        password: str | None = None,
        use_keychain: bool = True,
    ) -> None:
        """Initialize Gmail provider.

        Args:
            user: Gmail address. If None, auto-detected from Keychain or env.
            password: App password. If None, loaded from Keychain or env.
            use_keychain: Whether to check macOS Keychain for credentials.
        """
        self._user = user
        self._password = password
        self._use_keychain = use_keychain

    @property
    def host(self) -> str:
        return "smtp.gmail.com"

    @property
    def port(self) -> int:
        return 587

    @property
    def use_tls(self) -> bool:
        return True

    def get_credentials(self) -> tuple[str, str]:
        """Get Gmail credentials.

        Returns:
            Tuple of (email, app_password).

        Raises:
            SMTPAuthError: If credentials cannot be found.
        """
        user = self._user
        password = self._password

        # If both provided, use them
        if user and password:
            return user, password

        # Try Keychain first (macOS only)
        if self._use_keychain and sys.platform == "darwin":
            kc_user, kc_password = self._get_keychain_credentials(user)
            if kc_user and kc_password:
                return kc_user, kc_password

        # Fall back to environment variables
        env_user = os.environ.get("GMAIL_SMTP_USER")
        env_password = os.environ.get("GMAIL_SMTP_PASSWORD")

        # Use explicit user if provided, otherwise env
        final_user = user or env_user
        final_password = password or env_password

        if not final_user:
            raise SMTPAuthError("Gmail user not found. Set GMAIL_SMTP_USER or pass user= argument.")
        if not final_password:
            raise SMTPAuthError(
                "Gmail password not found. "
                "Store in Keychain or set GMAIL_SMTP_PASSWORD env var.\n"
                "To store in Keychain: auth-utils email store-password gmail"
            )

        return final_user, final_password

    def _get_keychain_credentials(
        self, user_hint: str | None = None
    ) -> tuple[str | None, str | None]:
        """Get credentials from macOS Keychain.

        Args:
            user_hint: If provided, only look for this specific account.

        Returns:
            Tuple of (user, password) or (None, None) if not found.
        """
        try:
            if user_hint:
                # Look for specific account
                result = subprocess.run(
                    [
                        "security",
                        "find-generic-password",
                        "-s",
                        KEYCHAIN_SERVICE,
                        "-a",
                        user_hint,
                        "-w",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                return user_hint, result.stdout.strip()
            else:
                # Get account name first
                result = subprocess.run(
                    [
                        "security",
                        "find-generic-password",
                        "-s",
                        KEYCHAIN_SERVICE,
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                # Parse account from output
                account = None
                for line in result.stdout.split("\n"):
                    if '"acct"<blob>=' in line:
                        # Extract value between quotes
                        start = line.find('="') + 2
                        end = line.rfind('"')
                        if start > 1 and end > start:
                            account = line[start:end]
                            break

                if not account:
                    return None, None

                # Now get password
                pw_result = subprocess.run(
                    [
                        "security",
                        "find-generic-password",
                        "-s",
                        KEYCHAIN_SERVICE,
                        "-a",
                        account,
                        "-w",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                return account, pw_result.stdout.strip()

        except subprocess.CalledProcessError:
            return None, None


def store_gmail_password(user: str, password: str) -> bool:
    """Store Gmail password in macOS Keychain.

    Args:
        user: Gmail address.
        password: App password.

    Returns:
        True if stored successfully.
    """
    if sys.platform != "darwin":
        return False

    try:
        # Delete existing entry if present
        subprocess.run(
            [
                "security",
                "delete-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                user,
            ],
            capture_output=True,
            check=False,
        )
        # Add new entry
        subprocess.run(
            [
                "security",
                "add-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
                "-a",
                user,
                "-w",
                password,
            ],
            capture_output=True,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_gmail_keychain_status() -> dict:
    """Check Gmail Keychain credential status.

    Returns:
        Dict with 'configured' bool and 'user' if found.
    """
    if sys.platform != "darwin":
        return {"configured": False, "user": None, "error": "Not macOS"}

    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                KEYCHAIN_SERVICE,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        # Parse account
        for line in result.stdout.split("\n"):
            if '"acct"<blob>=' in line:
                start = line.find('="') + 2
                end = line.rfind('"')
                if start > 1 and end > start:
                    return {"configured": True, "user": line[start:end]}
        return {"configured": False, "user": None}
    except subprocess.CalledProcessError:
        return {"configured": False, "user": None}
