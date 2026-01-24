"""Google Drive API client with OAuth authentication.

Manage Google Drive files programmatically with OAuth 2.0 authentication.

Usage:
    from auth_utils.drive import DriveClient

    # Initialize (requires OAuth authorization)
    client = DriveClient()

    # List files
    files = client.list_files()

    # Upload a file
    file = client.upload_file("document.pdf", "/path/to/document.pdf")

    # Download a file
    client.download_file(file.id, "/path/to/download.pdf")

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils drive auth
"""

from __future__ import annotations

from auth_utils.drive.client import DriveClient, DriveFile

__all__ = ["DriveClient", "DriveFile"]
