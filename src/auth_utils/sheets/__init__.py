"""Google Sheets API client with OAuth authentication.

Manage Google Sheets programmatically with OAuth 2.0 authentication.

Usage:
    from auth_utils.sheets import SheetsClient

    # Initialize (requires OAuth authorization)
    client = SheetsClient()

    # Create a spreadsheet
    sheet = client.create_spreadsheet("My Spreadsheet")

    # Read values
    values = client.read_range(sheet.id, "Sheet1!A1:C10")

    # Write values
    client.write_range(sheet.id, "Sheet1!A1", [["Name", "Age"], ["Alice", 30]])

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils sheets auth
"""

from __future__ import annotations

from auth_utils.sheets.client import SheetsClient, Spreadsheet

__all__ = ["SheetsClient", "Spreadsheet"]
