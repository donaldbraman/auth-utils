"""Google Drive API client implementation."""

from __future__ import annotations

import contextlib
import io
import mimetypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class DriveFile:
    """Represents a Google Drive file."""

    id: str
    name: str
    mime_type: str
    size: int | None = None
    created_time: datetime | None = None
    modified_time: datetime | None = None
    parents: list[str] | None = None
    web_view_link: str | None = None
    is_folder: bool = False

    @property
    def extension(self) -> str | None:
        """Get file extension from name."""
        if "." in self.name:
            return self.name.rsplit(".", 1)[-1].lower()
        return None


# Common MIME types
FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"
GOOGLE_DOC_MIME_TYPE = "application/vnd.google-apps.document"
GOOGLE_SHEET_MIME_TYPE = "application/vnd.google-apps.spreadsheet"
GOOGLE_SLIDES_MIME_TYPE = "application/vnd.google-apps.presentation"


class DriveClient:
    """Google Drive API client with OAuth authentication.

    Provides access to Google Drive for managing files and folders.

    Usage:
        client = DriveClient()

        # List files
        files = client.list_files()

        # Upload a file
        file = client.upload_file("document.pdf", "/path/to/document.pdf")

        # Download a file
        client.download_file(file.id, "/path/to/download.pdf")

        # Create a folder
        folder = client.create_folder("My Folder")

    Note:
        Requires OAuth authorization. Run `auth-utils drive auth` to authorize.
    """

    def __init__(
        self,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Drive client.

        Args:
            scopes: OAuth scopes. Defaults to ["drive"].
        """
        self._scopes = scopes or ["drive"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None

    def _get_service(self) -> Any:
        """Get or create Drive API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Drive API requires OAuth authorization. "
                    "Run 'auth-utils drive auth' to authorize.",
                )
            self._service = self._auth.build_service("drive", "v3")
        return self._service

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

    # =========================================================================
    # Files
    # =========================================================================

    def list_files(
        self,
        max_results: int = 100,
        query: str | None = None,
        folder_id: str | None = None,
        include_folders: bool = True,
        order_by: str = "modifiedTime desc",
    ) -> list[DriveFile]:
        """List files in Drive.

        Args:
            max_results: Maximum number of files to return.
            query: Search query (Drive query syntax).
            folder_id: Only list files in this folder.
            include_folders: Include folders in results.
            order_by: Sort order (e.g., "name", "modifiedTime desc").

        Returns:
            List of DriveFile objects.
        """
        service = self._get_service()

        # Build query
        query_parts = []
        if query:
            query_parts.append(query)
        if folder_id:
            query_parts.append(f"'{folder_id}' in parents")
        if not include_folders:
            query_parts.append(f"mimeType != '{FOLDER_MIME_TYPE}'")

        # Don't include trashed files
        query_parts.append("trashed = false")

        full_query = " and ".join(query_parts) if query_parts else None

        kwargs: dict[str, Any] = {
            "pageSize": max_results,
            "fields": "files(id, name, mimeType, size, createdTime, modifiedTime, parents, webViewLink)",
            "orderBy": order_by,
        }
        if full_query:
            kwargs["q"] = full_query

        results = service.files().list(**kwargs).execute()
        items = results.get("files", [])

        return [self._parse_file(item) for item in items]

    def get_file(self, file_id: str) -> DriveFile | None:
        """Get a specific file by ID.

        Args:
            file_id: Drive file ID.

        Returns:
            DriveFile or None if not found.
        """
        service = self._get_service()
        try:
            result = (
                service.files()
                .get(
                    fileId=file_id,
                    fields="id, name, mimeType, size, createdTime, modifiedTime, parents, webViewLink",
                )
                .execute()
            )
            return self._parse_file(result)
        except Exception:
            return None

    def upload_file(
        self,
        name: str,
        file_path: str | Path,
        folder_id: str | None = None,
        mime_type: str | None = None,
    ) -> DriveFile:
        """Upload a file to Drive.

        Args:
            name: Name for the file in Drive.
            file_path: Local path to the file to upload.
            folder_id: Parent folder ID (optional).
            mime_type: MIME type (auto-detected if not provided).

        Returns:
            Created DriveFile.
        """
        service = self._get_service()
        file_path = Path(file_path)

        # Auto-detect MIME type
        if mime_type is None:
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type is None:
                mime_type = "application/octet-stream"

        # Build metadata
        metadata: dict[str, Any] = {"name": name}
        if folder_id:
            metadata["parents"] = [folder_id]

        media = MediaFileUpload(str(file_path), mimetype=mime_type, resumable=True)

        result = (
            service.files()
            .create(
                body=metadata,
                media_body=media,
                fields="id, name, mimeType, size, createdTime, modifiedTime, parents, webViewLink",
            )
            .execute()
        )

        return self._parse_file(result)

    def download_file(self, file_id: str, output_path: str | Path) -> bool:
        """Download a file from Drive.

        Args:
            file_id: Drive file ID.
            output_path: Local path to save the file.

        Returns:
            True if download successful.
        """
        service = self._get_service()
        output_path = Path(output_path)

        try:
            # Get file metadata to check if it's a Google Doc
            file_meta = service.files().get(fileId=file_id, fields="mimeType").execute()
            mime_type = file_meta.get("mimeType", "")

            # Handle Google Docs export
            if mime_type.startswith("application/vnd.google-apps."):
                return self._export_google_doc(file_id, mime_type, output_path)

            # Regular file download
            request = service.files().get_media(fileId=file_id)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)

            done = False
            while not done:
                _, done = downloader.next_chunk()

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(fh.getvalue())

            return True
        except Exception:
            return False

    def _export_google_doc(self, file_id: str, mime_type: str, output_path: Path) -> bool:
        """Export a Google Doc to a file."""
        service = self._get_service()

        # Determine export MIME type
        export_mime_types = {
            GOOGLE_DOC_MIME_TYPE: "application/pdf",
            GOOGLE_SHEET_MIME_TYPE: "text/csv",
            GOOGLE_SLIDES_MIME_TYPE: "application/pdf",
        }

        export_mime = export_mime_types.get(mime_type, "application/pdf")

        try:
            request = service.files().export_media(fileId=file_id, mimeType=export_mime)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, request)

            done = False
            while not done:
                _, done = downloader.next_chunk()

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(fh.getvalue())

            return True
        except Exception:
            return False

    def delete_file(self, file_id: str) -> bool:
        """Delete a file from Drive.

        Args:
            file_id: Drive file ID.

        Returns:
            True if deleted successfully.
        """
        service = self._get_service()
        try:
            service.files().delete(fileId=file_id).execute()
            return True
        except Exception:
            return False

    def move_file(self, file_id: str, new_folder_id: str) -> DriveFile | None:
        """Move a file to a different folder.

        Args:
            file_id: Drive file ID.
            new_folder_id: Target folder ID.

        Returns:
            Updated DriveFile or None if failed.
        """
        service = self._get_service()
        try:
            # Get current parents
            file = service.files().get(fileId=file_id, fields="parents").execute()
            previous_parents = ",".join(file.get("parents", []))

            # Move file
            result = (
                service.files()
                .update(
                    fileId=file_id,
                    addParents=new_folder_id,
                    removeParents=previous_parents,
                    fields="id, name, mimeType, size, createdTime, modifiedTime, parents, webViewLink",
                )
                .execute()
            )

            return self._parse_file(result)
        except Exception:
            return None

    # =========================================================================
    # Folders
    # =========================================================================

    def create_folder(self, name: str, parent_id: str | None = None) -> DriveFile:
        """Create a new folder.

        Args:
            name: Folder name.
            parent_id: Parent folder ID (optional).

        Returns:
            Created folder as DriveFile.
        """
        service = self._get_service()

        metadata: dict[str, Any] = {
            "name": name,
            "mimeType": FOLDER_MIME_TYPE,
        }
        if parent_id:
            metadata["parents"] = [parent_id]

        result = (
            service.files()
            .create(
                body=metadata,
                fields="id, name, mimeType, size, createdTime, modifiedTime, parents, webViewLink",
            )
            .execute()
        )

        return self._parse_file(result)

    def list_folders(self, parent_id: str | None = None, max_results: int = 100) -> list[DriveFile]:
        """List folders in Drive.

        Args:
            parent_id: Only list folders in this parent folder.
            max_results: Maximum number of folders to return.

        Returns:
            List of DriveFile objects (folders only).
        """
        query = f"mimeType = '{FOLDER_MIME_TYPE}'"
        return self.list_files(
            max_results=max_results,
            query=query,
            folder_id=parent_id,
            include_folders=True,
        )

    def _parse_file(self, data: dict) -> DriveFile:
        """Parse file from API response."""
        created_time = None
        if data.get("createdTime"):
            with contextlib.suppress(Exception):
                created_time = datetime.fromisoformat(data["createdTime"].replace("Z", "+00:00"))

        modified_time = None
        if data.get("modifiedTime"):
            with contextlib.suppress(Exception):
                modified_time = datetime.fromisoformat(data["modifiedTime"].replace("Z", "+00:00"))

        size = None
        if data.get("size"):
            with contextlib.suppress(Exception):
                size = int(data["size"])

        mime_type = data.get("mimeType", "")
        is_folder = mime_type == FOLDER_MIME_TYPE

        return DriveFile(
            id=data["id"],
            name=data.get("name", ""),
            mime_type=mime_type,
            size=size,
            created_time=created_time,
            modified_time=modified_time,
            parents=data.get("parents"),
            web_view_link=data.get("webViewLink"),
            is_folder=is_folder,
        )
