"""Email/SMTP exceptions."""

from __future__ import annotations


class SMTPError(Exception):
    """Base exception for SMTP errors."""


class SMTPAuthError(SMTPError):
    """Authentication failed."""


class SMTPConnectionError(SMTPError):
    """Failed to connect to SMTP server."""


class SMTPSendError(SMTPError):
    """Failed to send email."""
