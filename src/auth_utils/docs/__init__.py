"""Google Docs API client with OAuth authentication.

Manage Google Docs programmatically with OAuth 2.0 authentication.

Usage:
    from auth_utils.docs import DocsClient

    # Initialize (requires OAuth authorization)
    client = DocsClient()

    # Create a document
    doc = client.create_document("My Document")

    # Get document content
    content = client.get_document(doc.id)

    # Append text to document
    client.append_text(doc.id, "Hello, World!")

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils docs auth
"""

from __future__ import annotations

from auth_utils.docs.client import DocsClient, Document

__all__ = ["DocsClient", "Document"]
