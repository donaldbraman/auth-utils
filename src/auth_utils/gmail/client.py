"""Gmail API client implementation."""

from __future__ import annotations

import base64
import contextlib
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class GmailMessage:
    """Represents a Gmail message."""

    id: str
    thread_id: str
    subject: str
    sender: str
    to: str
    date: datetime | None
    snippet: str
    body: str
    html: str | None = None
    labels: list[str] | None = None

    @property
    def preview(self) -> str:
        """Get message snippet as preview."""
        return self.snippet


class GmailClient:
    """Gmail API client with OAuth authentication.

    Provides access to Gmail via the Gmail API, offering richer features
    than IMAP including Gmail's native search syntax, labels, and
    thread-based conversation views.

    Usage:
        client = GmailClient()

        # Search with Gmail query syntax
        messages = client.search("from:student@gwu.edu subject:absent")

        # Read messages
        for msg in messages:
            print(msg.subject, msg.sender)
            print(msg.body)

        # List labels
        labels = client.list_labels()

    Note:
        Requires OAuth authorization. Run `auth-utils gmail auth` to authorize.
    """

    def __init__(
        self,
        user: str = "me",
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Gmail client.

        Args:
            user: Gmail user ID or "me" for authenticated user.
            scopes: OAuth scopes. Defaults to ["gmail_readonly"].
        """
        self._user = user
        self._scopes = scopes or ["gmail_readonly"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None

    def _get_service(self) -> Any:
        """Get or create Gmail API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Gmail API requires OAuth authorization. "
                    "Run 'auth-utils gmail auth' to authorize.",
                )
            self._service = self._auth.build_service("gmail", "v1")
        return self._service

    @property
    def user_email(self) -> str:
        """Get the authenticated user's email address."""
        service = self._get_service()
        profile = service.users().getProfile(userId=self._user).execute()
        return profile.get("emailAddress", "")

    def authorize(self, timeout: int = 120) -> bool:
        """Perform interactive OAuth authorization.

        Args:
            timeout: Seconds to wait for OAuth callback.

        Returns:
            True if authorization successful.

        Raises:
            AuthorizationRequired: If browser cannot be opened.
            TokenError: If authorization fails.
        """
        self._auth = GoogleOAuth(scopes=self._scopes)
        self._auth.authorize(timeout=timeout)
        self._service = None  # Force service recreation
        return True

    def is_authorized(self) -> bool:
        """Check if client is authorized."""
        try:
            auth = GoogleOAuth(scopes=self._scopes)
            return auth.is_authorized()
        except Exception:
            return False

    def search(
        self,
        query: str = "",
        max_results: int = 50,
        include_body: bool = True,
    ) -> list[GmailMessage]:
        """Search for emails using Gmail query syntax.

        Args:
            query: Gmail search query (e.g., "from:user@example.com subject:test").
                  See https://support.google.com/mail/answer/7190 for syntax.
            max_results: Maximum number of messages to return.
            include_body: Whether to fetch full message body.

        Returns:
            List of GmailMessage objects matching the query.
        """
        service = self._get_service()

        # Search for message IDs
        results = (
            service.users()
            .messages()
            .list(userId=self._user, q=query, maxResults=max_results)
            .execute()
        )

        messages = results.get("messages", [])
        if not messages:
            return []

        # Fetch full message details
        gmail_messages = []
        for msg_ref in messages:
            msg = self._fetch_message(msg_ref["id"], include_body)
            if msg:
                gmail_messages.append(msg)

        return gmail_messages

    def get_message(self, message_id: str, include_body: bool = True) -> GmailMessage | None:
        """Get a single message by ID.

        Args:
            message_id: Gmail message ID.
            include_body: Whether to fetch full message body.

        Returns:
            GmailMessage or None if not found.
        """
        return self._fetch_message(message_id, include_body)

    def _fetch_message(self, message_id: str, include_body: bool = True) -> GmailMessage | None:
        """Fetch a single message with full details."""
        service = self._get_service()

        try:
            format_type = "full" if include_body else "metadata"
            msg = (
                service.users()
                .messages()
                .get(userId=self._user, id=message_id, format=format_type)
                .execute()
            )
        except Exception:
            return None

        # Parse headers
        headers = {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", [])}

        subject = headers.get("subject", "")
        sender = headers.get("from", "")
        to_addr = headers.get("to", "")
        date_str = headers.get("date", "")

        # Parse date
        msg_date = None
        if date_str:
            with contextlib.suppress(Exception):
                msg_date = parsedate_to_datetime(date_str)

        # Get snippet
        snippet = msg.get("snippet", "")

        # Extract body
        body = ""
        html = None
        if include_body:
            body, html = self._extract_body(msg.get("payload", {}))

        # Get labels
        labels = msg.get("labelIds", [])

        return GmailMessage(
            id=msg["id"],
            thread_id=msg.get("threadId", ""),
            subject=subject,
            sender=sender,
            to=to_addr,
            date=msg_date,
            snippet=snippet,
            body=body,
            html=html,
            labels=labels,
        )

    def _extract_body(self, payload: dict) -> tuple[str, str | None]:
        """Extract plain text and HTML body from message payload.

        Returns:
            Tuple of (plain_text, html_or_none).
        """
        plain_body = ""
        html_body = None

        def decode_part(part: dict) -> str:
            """Decode a message part."""
            data = part.get("body", {}).get("data", "")
            if data:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
            return ""

        def process_part(part: dict) -> None:
            nonlocal plain_body, html_body
            mime_type = part.get("mimeType", "")

            if mime_type == "text/plain" and not plain_body:
                plain_body = decode_part(part)
            elif mime_type == "text/html" and not html_body:
                html_body = decode_part(part)
            elif "parts" in part:
                for subpart in part["parts"]:
                    process_part(subpart)

        # Check if payload has direct body
        if payload.get("body", {}).get("data"):
            mime_type = payload.get("mimeType", "")
            decoded = decode_part(payload)
            if mime_type == "text/html":
                html_body = decoded
            else:
                plain_body = decoded
        elif "parts" in payload:
            for part in payload["parts"]:
                process_part(part)

        return plain_body, html_body

    def list_labels(self) -> list[dict[str, str]]:
        """List all Gmail labels.

        Returns:
            List of dicts with 'id' and 'name' keys.
        """
        service = self._get_service()
        results = service.users().labels().list(userId=self._user).execute()
        labels = results.get("labels", [])
        return [{"id": label["id"], "name": label["name"]} for label in labels]

    def get_threads(
        self,
        query: str = "",
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Get email threads matching a query.

        Args:
            query: Gmail search query.
            max_results: Maximum number of threads to return.

        Returns:
            List of thread metadata dicts.
        """
        service = self._get_service()
        results = (
            service.users()
            .threads()
            .list(userId=self._user, q=query, maxResults=max_results)
            .execute()
        )
        return results.get("threads", [])
