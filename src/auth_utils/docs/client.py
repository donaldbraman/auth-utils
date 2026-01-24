"""Google Docs API client implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class Document:
    """Represents a Google Doc."""

    id: str
    title: str
    body_text: str = ""
    revision_id: str | None = None

    @property
    def word_count(self) -> int:
        """Get approximate word count."""
        return len(self.body_text.split())


class DocsClient:
    """Google Docs API client with OAuth authentication.

    Provides access to Google Docs for creating and editing documents.

    Usage:
        client = DocsClient()

        # Create a document
        doc = client.create_document("My Document")

        # Get document content
        doc = client.get_document(doc.id)
        print(doc.body_text)

        # Append text
        client.append_text(doc.id, "Hello, World!")

    Note:
        Requires OAuth authorization. Run `auth-utils docs auth` to authorize.
    """

    def __init__(
        self,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Docs client.

        Args:
            scopes: OAuth scopes. Defaults to ["docs", "drive_file"].
        """
        # Need drive_file scope to create documents
        self._scopes = scopes or ["docs", "drive_file"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None
        self._drive_service: Any = None

    def _get_service(self) -> Any:
        """Get or create Docs API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Docs API requires OAuth authorization. "
                    "Run 'auth-utils docs auth' to authorize.",
                )
            self._service = self._auth.build_service("docs", "v1")
        return self._service

    def _get_drive_service(self) -> Any:
        """Get or create Drive API service for file operations."""
        if self._drive_service is None:
            if self._auth is None:
                self._get_service()  # Initialize auth
            self._drive_service = self._auth.build_service("drive", "v3")
        return self._drive_service

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
        self._drive_service = None
        return True

    def is_authorized(self) -> bool:
        """Check if client is authorized."""
        try:
            auth = GoogleOAuth(scopes=self._scopes)
            return auth.is_authorized()
        except Exception:
            return False

    # =========================================================================
    # Documents
    # =========================================================================

    def get_document(self, document_id: str) -> Document | None:
        """Get a document by ID.

        Args:
            document_id: Google Docs document ID.

        Returns:
            Document or None if not found.
        """
        service = self._get_service()
        try:
            result = service.documents().get(documentId=document_id).execute()
            return self._parse_document(result)
        except Exception:
            return None

    def create_document(self, title: str, body_text: str | None = None) -> Document:
        """Create a new document.

        Args:
            title: Document title.
            body_text: Initial body text (optional).

        Returns:
            Created Document.
        """
        service = self._get_service()

        # Create empty document
        result = service.documents().create(body={"title": title}).execute()
        doc_id = result["documentId"]

        # Add initial content if provided
        if body_text:
            self.append_text(doc_id, body_text)
            # Refresh to get updated content
            result = service.documents().get(documentId=doc_id).execute()

        return self._parse_document(result)

    def append_text(self, document_id: str, text: str) -> bool:
        """Append text to the end of a document.

        Args:
            document_id: Document ID.
            text: Text to append.

        Returns:
            True if successful.
        """
        service = self._get_service()
        try:
            # Get current document to find end index
            doc = service.documents().get(documentId=document_id).execute()
            end_index = doc["body"]["content"][-1]["endIndex"] - 1

            requests = [
                {
                    "insertText": {
                        "location": {"index": end_index},
                        "text": text,
                    }
                }
            ]

            service.documents().batchUpdate(
                documentId=document_id, body={"requests": requests}
            ).execute()

            return True
        except Exception:
            return False

    def insert_text(self, document_id: str, text: str, index: int = 1) -> bool:
        """Insert text at a specific position.

        Args:
            document_id: Document ID.
            text: Text to insert.
            index: Position to insert at (1 = beginning).

        Returns:
            True if successful.
        """
        service = self._get_service()
        try:
            requests = [
                {
                    "insertText": {
                        "location": {"index": index},
                        "text": text,
                    }
                }
            ]

            service.documents().batchUpdate(
                documentId=document_id, body={"requests": requests}
            ).execute()

            return True
        except Exception:
            return False

    def replace_text(self, document_id: str, old_text: str, new_text: str) -> int:
        """Replace all occurrences of text in a document.

        Args:
            document_id: Document ID.
            old_text: Text to find.
            new_text: Replacement text.

        Returns:
            Number of replacements made.
        """
        service = self._get_service()
        try:
            requests = [
                {
                    "replaceAllText": {
                        "containsText": {"text": old_text, "matchCase": True},
                        "replaceText": new_text,
                    }
                }
            ]

            result = (
                service.documents()
                .batchUpdate(documentId=document_id, body={"requests": requests})
                .execute()
            )

            # Get replacement count from response
            replies = result.get("replies", [])
            if replies and "replaceAllText" in replies[0]:
                return replies[0]["replaceAllText"].get("occurrencesChanged", 0)
            return 0
        except Exception:
            return 0

    def clear_document(self, document_id: str) -> bool:
        """Clear all content from a document.

        Args:
            document_id: Document ID.

        Returns:
            True if successful.
        """
        service = self._get_service()
        try:
            # Get document to find content range
            doc = service.documents().get(documentId=document_id).execute()
            content = doc["body"]["content"]

            if len(content) <= 1:
                return True  # Already empty

            # Find the range to delete (skip the initial newline)
            start_index = 1
            end_index = content[-1]["endIndex"] - 1

            if end_index <= start_index:
                return True

            requests = [
                {
                    "deleteContentRange": {
                        "range": {
                            "startIndex": start_index,
                            "endIndex": end_index,
                        }
                    }
                }
            ]

            service.documents().batchUpdate(
                documentId=document_id, body={"requests": requests}
            ).execute()

            return True
        except Exception:
            return False

    def delete_document(self, document_id: str) -> bool:
        """Delete a document.

        Args:
            document_id: Document ID.

        Returns:
            True if deleted successfully.
        """
        drive_service = self._get_drive_service()
        try:
            drive_service.files().delete(fileId=document_id).execute()
            return True
        except Exception:
            return False

    def _parse_document(self, data: dict) -> Document:
        """Parse document from API response."""
        # Extract body text from content
        body_text = ""
        content = data.get("body", {}).get("content", [])

        for element in content:
            if "paragraph" in element:
                for para_element in element["paragraph"].get("elements", []):
                    if "textRun" in para_element:
                        body_text += para_element["textRun"].get("content", "")

        return Document(
            id=data["documentId"],
            title=data.get("title", ""),
            body_text=body_text,
            revision_id=data.get("revisionId"),
        )
