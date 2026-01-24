"""Email authentication support (SMTP and IMAP).

Send and read emails via Gmail with centralized credential management.
Supports macOS Keychain for secure password storage.

Sending emails (SMTP):
    from auth_utils.email import SMTPClient

    client = SMTPClient(provider="gmail")
    client.send(
        to=["recipient@example.com"],
        subject="Hello",
        body="Message body",
    )

Reading emails (IMAP):
    from auth_utils.email import IMAPClient

    with IMAPClient(provider="gmail") as client:
        messages = client.search(
            subject="absent",
            since=date(2026, 1, 20),
        )
        for msg in messages:
            print(msg.subject, msg.sender)
            print(msg.body)

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
from auth_utils.email.imap import EmailMessage, IMAPClient
from auth_utils.email.smtp import SMTPClient

__all__ = [
    "SMTPClient",
    "IMAPClient",
    "EmailMessage",
    "SMTPError",
    "SMTPAuthError",
    "SMTPConnectionError",
    "SMTPSendError",
]
