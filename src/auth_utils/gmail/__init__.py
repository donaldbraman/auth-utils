"""Gmail API client with OAuth authentication.

Access Gmail via the Gmail API with OAuth 2.0 authentication.
Provides richer features than IMAP including Gmail search syntax,
labels, and thread-based conversation views.

Usage:
    from auth_utils.gmail import GmailClient

    # Initialize (requires OAuth authorization)
    client = GmailClient()

    # Search with Gmail query syntax
    messages = client.search("from:student@gwu.edu subject:absent after:2026/01/20")

    # Read messages
    for msg in messages:
        print(msg.subject, msg.sender, msg.date)
        print(msg.snippet)
        print(msg.body)

    # List labels
    labels = client.list_labels()

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils gmail auth
"""

from __future__ import annotations

from auth_utils.gmail.client import GmailClient, GmailMessage

__all__ = ["GmailClient", "GmailMessage"]
