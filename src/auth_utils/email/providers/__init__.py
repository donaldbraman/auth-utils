"""SMTP providers."""

from __future__ import annotations

from auth_utils.email.providers.base import BaseSMTPProvider
from auth_utils.email.providers.gmail import GmailProvider

__all__ = ["BaseSMTPProvider", "GmailProvider"]
