"""Email/SMTP authentication support.

Send emails via Gmail SMTP with centralized credential management.
Supports macOS Keychain for secure password storage.

Usage:
    from auth_utils.email import SMTPClient

    # Auto-detect credentials from Keychain or environment
    client = SMTPClient(provider="gmail")
    client.send(
        to=["recipient@example.com"],
        subject="Hello",
        body="Message body",
    )

    # HTML email with explicit credentials
    client = SMTPClient(
        provider="gmail",
        user="sender@gmail.com",
        password="app-password",
    )
    client.send(
        to=["recipient@example.com"],
        subject="Hello",
        body="<h1>HTML Message</h1>",
        html=True,
    )

Credential lookup order:
    1. Explicit user/password arguments
    2. macOS Keychain (service: auth-utils-gmail)
    3. Environment variables (GMAIL_SMTP_USER, GMAIL_SMTP_PASSWORD)
"""

from __future__ import annotations

from auth_utils.email.exceptions import (
    SMTPAuthError,
    SMTPConnectionError,
    SMTPError,
    SMTPSendError,
)
from auth_utils.email.smtp import SMTPClient

__all__ = [
    "SMTPClient",
    "SMTPError",
    "SMTPAuthError",
    "SMTPConnectionError",
    "SMTPSendError",
]
