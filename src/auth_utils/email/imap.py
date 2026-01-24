"""IMAP client for reading emails."""

from __future__ import annotations

import contextlib
import email
import imaplib
import re
from dataclasses import dataclass
from datetime import date, datetime
from email.header import decode_header
from email.utils import parsedate_to_datetime

from auth_utils.email.exceptions import SMTPAuthError, SMTPConnectionError
from auth_utils.email.providers.gmail import GmailProvider


@dataclass
class EmailMessage:
    """Represents an email message."""

    uid: str
    subject: str
    sender: str
    to: str
    date: datetime | None
    body: str
    html: str | None = None

    @property
    def snippet(self) -> str:
        """Get first 100 chars of body as preview."""
        text = self.body.strip()
        if len(text) > 100:
            return text[:100] + "..."
        return text


class IMAPClient:
    """IMAP client for reading emails.

    Usage:
        # Auto-detect credentials from Keychain/env
        client = IMAPClient(provider="gmail")

        # Search emails
        messages = client.search(
            folder="INBOX",
            from_="student@gwu.edu",
            subject="absent",
            since=date(2026, 1, 20),
        )

        # Read messages
        for msg in messages:
            print(msg.subject, msg.sender, msg.date)
            print(msg.body)

        # Don't forget to close when done
        client.close()

    Context manager usage:
        with IMAPClient(provider="gmail") as client:
            messages = client.search(subject="test")
    """

    # IMAP server settings by provider
    SERVERS = {
        "gmail": ("imap.gmail.com", 993),
    }

    def __init__(
        self,
        provider: str = "gmail",
        user: str | None = None,
        password: str | None = None,
        use_keychain: bool = True,
    ) -> None:
        """Initialize IMAP client.

        Args:
            provider: Provider name ("gmail").
            user: Email address for authentication.
            password: Password or app password.
            use_keychain: Whether to check macOS Keychain for credentials.

        Raises:
            ValueError: If provider is not supported.
        """
        if provider not in self.SERVERS:
            raise ValueError(
                f"Unknown provider: {provider}. Supported: {list(self.SERVERS.keys())}"
            )

        self._provider_name = provider
        self._host, self._port = self.SERVERS[provider]

        # Reuse Gmail provider for credential lookup
        self._cred_provider = GmailProvider(
            user=user,
            password=password,
            use_keychain=use_keychain,
        )

        self._connection: imaplib.IMAP4_SSL | None = None

    def __enter__(self) -> IMAPClient:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

    @property
    def user(self) -> str:
        """Get the authenticated user email."""
        user, _ = self._cred_provider.get_credentials()
        return user

    def connect(self) -> None:
        """Connect and authenticate to IMAP server.

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Connection failed.
        """
        if self._connection:
            return

        user, password = self._cred_provider.get_credentials()

        try:
            self._connection = imaplib.IMAP4_SSL(self._host, self._port)
        except Exception as e:
            raise SMTPConnectionError(f"Failed to connect to {self._host}:{self._port}: {e}") from e

        try:
            self._connection.login(user, password)
        except imaplib.IMAP4.error as e:
            self._connection = None
            raise SMTPAuthError(f"IMAP authentication failed: {e}") from e

    def close(self) -> None:
        """Close IMAP connection."""
        if self._connection:
            with contextlib.suppress(Exception):
                self._connection.logout()
            self._connection = None

    def list_folders(self) -> list[str]:
        """List available mail folders.

        Returns:
            List of folder names.
        """
        self.connect()
        assert self._connection is not None

        status, folders = self._connection.list()
        if status != "OK":
            return []

        result = []
        for folder_data in folders:
            if folder_data:
                # Parse folder name from response like: (\\HasNoChildren) "/" "INBOX"
                match = re.search(
                    r'"([^"]+)"$',
                    folder_data.decode() if isinstance(folder_data, bytes) else folder_data,
                )
                if match:
                    result.append(match.group(1))
        return result

    def search(
        self,
        folder: str = "INBOX",
        from_: str | None = None,
        to: str | None = None,
        subject: str | None = None,
        since: date | None = None,
        before: date | None = None,
        unseen: bool = False,
        limit: int = 50,
    ) -> list[EmailMessage]:
        """Search for emails matching criteria.

        Args:
            folder: Mailbox folder to search.
            from_: Filter by sender (partial match).
            to: Filter by recipient (partial match).
            subject: Filter by subject (partial match).
            since: Messages since this date (inclusive).
            before: Messages before this date (exclusive).
            unseen: Only return unread messages.
            limit: Maximum number of messages to return.

        Returns:
            List of matching EmailMessage objects.
        """
        self.connect()
        assert self._connection is not None

        # Select folder
        status, _ = self._connection.select(folder, readonly=True)
        if status != "OK":
            return []

        # Build search criteria
        criteria = []
        if from_:
            criteria.append(f'FROM "{from_}"')
        if to:
            criteria.append(f'TO "{to}"')
        if subject:
            criteria.append(f'SUBJECT "{subject}"')
        if since:
            criteria.append(f"SINCE {since.strftime('%d-%b-%Y')}")
        if before:
            criteria.append(f"BEFORE {before.strftime('%d-%b-%Y')}")
        if unseen:
            criteria.append("UNSEEN")

        search_str = " ".join(criteria) if criteria else "ALL"

        # Search
        status, data = self._connection.search(None, search_str)
        if status != "OK" or not data[0]:
            return []

        # Get message UIDs (most recent first)
        uids = data[0].split()
        uids = list(reversed(uids))[:limit]

        # Fetch messages
        messages = []
        for uid in uids:
            msg = self._fetch_message(uid)
            if msg:
                messages.append(msg)

        return messages

    def _fetch_message(self, uid: bytes) -> EmailMessage | None:
        """Fetch a single message by UID."""
        assert self._connection is not None

        status, data = self._connection.fetch(uid, "(RFC822)")
        if status != "OK" or not data or not data[0]:
            return None

        raw_email = data[0][1]
        if not isinstance(raw_email, bytes):
            return None

        msg = email.message_from_bytes(raw_email)

        # Parse headers
        subject = self._decode_header(msg.get("Subject", ""))
        sender = self._decode_header(msg.get("From", ""))
        to_addr = self._decode_header(msg.get("To", ""))

        # Parse date
        date_str = msg.get("Date")
        msg_date = None
        if date_str:
            with contextlib.suppress(Exception):
                msg_date = parsedate_to_datetime(date_str)

        # Extract body
        body, html = self._extract_body(msg)

        return EmailMessage(
            uid=uid.decode() if isinstance(uid, bytes) else str(uid),
            subject=subject,
            sender=sender,
            to=to_addr,
            date=msg_date,
            body=body,
            html=html,
        )

    def _decode_header(self, header: str | None) -> str:
        """Decode email header value."""
        if not header:
            return ""

        decoded_parts = []
        for part, encoding in decode_header(header):
            if isinstance(part, bytes):
                decoded_parts.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                decoded_parts.append(part)
        return " ".join(decoded_parts)

    def _extract_body(self, msg: email.message.Message) -> tuple[str, str | None]:
        """Extract plain text and HTML body from message.

        Returns:
            Tuple of (plain_text, html_or_none).
        """
        plain_body = ""
        html_body = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")

                    if content_type == "text/plain" and not plain_body:
                        plain_body = text
                    elif content_type == "text/html" and not html_body:
                        html_body = text
                except Exception:
                    continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    plain_body = payload.decode(charset, errors="replace")
            except Exception:
                plain_body = str(msg.get_payload())

        return plain_body, html_body

    def test_connection(self) -> bool:
        """Test IMAP connection and authentication.

        Returns:
            True if connection and auth succeed.

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Failed to connect.
        """
        self.connect()
        return True
