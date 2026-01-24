"""SMTP client for sending emails."""

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

from auth_utils.email.exceptions import (
    SMTPAuthError,
    SMTPConnectionError,
    SMTPSendError,
)
from auth_utils.email.providers.gmail import GmailProvider

if TYPE_CHECKING:
    from auth_utils.email.providers.base import BaseSMTPProvider

# Provider registry
PROVIDERS: dict[str, type[BaseSMTPProvider]] = {
    "gmail": GmailProvider,
}


class SMTPClient:
    """SMTP client for sending emails.

    Usage:
        # Simple - auto-detect credentials from Keychain/env
        client = SMTPClient(provider="gmail")
        client.send(
            to=["recipient@example.com"],
            subject="Hello",
            body="Message body",
        )

        # Explicit credentials
        client = SMTPClient(
            provider="gmail",
            user="sender@gmail.com",
            password="app-password",
        )

        # HTML email
        client.send(
            to=["recipient@example.com"],
            subject="Hello",
            body="<h1>HTML Message</h1>",
            html=True,
        )
    """

    def __init__(
        self,
        provider: str = "gmail",
        user: str | None = None,
        password: str | None = None,
        use_keychain: bool = True,
    ) -> None:
        """Initialize SMTP client.

        Args:
            provider: Provider name ("gmail").
            user: Email address for authentication.
            password: Password or app password.
            use_keychain: Whether to check macOS Keychain for credentials.

        Raises:
            ValueError: If provider is not supported.
        """
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}. Supported: {list(PROVIDERS.keys())}")

        provider_cls = PROVIDERS[provider]
        self._provider: BaseSMTPProvider = provider_cls(
            user=user,
            password=password,
            use_keychain=use_keychain,
        )

    @property
    def user(self) -> str:
        """Get the authenticated user email."""
        user, _ = self._provider.get_credentials()
        return user

    def send(
        self,
        to: list[str],
        subject: str,
        body: str,
        html: bool = False,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        from_name: str | None = None,
    ) -> None:
        """Send an email.

        Args:
            to: List of recipient email addresses.
            subject: Email subject line.
            body: Email body (plain text or HTML).
            html: If True, body is HTML; otherwise plain text.
            cc: List of CC recipients.
            bcc: List of BCC recipients.
            from_name: Display name for sender (e.g., "Professor Smith").

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Failed to connect to server.
            SMTPSendError: Failed to send email.
        """
        user, password = self._provider.get_credentials()

        # Build message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["To"] = ", ".join(to)

        if from_name:
            msg["From"] = f"{from_name} <{user}>"
        else:
            msg["From"] = user

        if cc:
            msg["Cc"] = ", ".join(cc)

        # Attach body
        content_type = "html" if html else "plain"
        msg.attach(MIMEText(body, content_type))

        # Calculate all recipients for SMTP
        all_recipients = list(to)
        if cc:
            all_recipients.extend(cc)
        if bcc:
            all_recipients.extend(bcc)

        # Send
        try:
            with smtplib.SMTP(self._provider.host, self._provider.port) as server:
                if self._provider.use_tls:
                    server.starttls()
                try:
                    server.login(user, password)
                except smtplib.SMTPAuthenticationError as e:
                    raise SMTPAuthError(f"Authentication failed: {e}") from e
                server.send_message(msg, to_addrs=all_recipients)
        except smtplib.SMTPConnectError as e:
            raise SMTPConnectionError(
                f"Failed to connect to {self._provider.host}:{self._provider.port}: {e}"
            ) from e
        except smtplib.SMTPException as e:
            if isinstance(e, smtplib.SMTPAuthenticationError):
                raise  # Already converted above
            raise SMTPSendError(f"Failed to send email: {e}") from e

    def test_connection(self) -> bool:
        """Test SMTP connection and authentication.

        Returns:
            True if connection and auth succeed.

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Failed to connect.
        """
        user, password = self._provider.get_credentials()

        try:
            with smtplib.SMTP(self._provider.host, self._provider.port) as server:
                if self._provider.use_tls:
                    server.starttls()
                try:
                    server.login(user, password)
                except smtplib.SMTPAuthenticationError as e:
                    raise SMTPAuthError(f"Authentication failed: {e}") from e
                return True
        except smtplib.SMTPConnectError as e:
            raise SMTPConnectionError(
                f"Failed to connect to {self._provider.host}:{self._provider.port}: {e}"
            ) from e
