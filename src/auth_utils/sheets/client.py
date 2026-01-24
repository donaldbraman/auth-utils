"""Google Sheets API client implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class Sheet:
    """Represents a sheet within a spreadsheet."""

    id: int
    title: str
    index: int
    row_count: int = 1000
    column_count: int = 26


@dataclass
class Spreadsheet:
    """Represents a Google Spreadsheet."""

    id: str
    title: str
    sheets: list[Sheet] | None = None
    url: str | None = None

    @property
    def default_sheet(self) -> Sheet | None:
        """Get the first sheet."""
        if self.sheets:
            return self.sheets[0]
        return None


class SheetsClient:
    """Google Sheets API client with OAuth authentication.

    Provides access to Google Sheets for reading and writing spreadsheet data.

    Usage:
        client = SheetsClient()

        # Create a spreadsheet
        sheet = client.create_spreadsheet("My Spreadsheet")

        # Read values
        values = client.read_range(sheet.id, "Sheet1!A1:C10")

        # Write values
        client.write_range(sheet.id, "Sheet1!A1", [["Name", "Age"], ["Alice", 30]])

        # Append rows
        client.append_rows(sheet.id, "Sheet1", [["Bob", 25], ["Carol", 35]])

    Note:
        Requires OAuth authorization. Run `auth-utils sheets auth` to authorize.
    """

    def __init__(
        self,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Sheets client.

        Args:
            scopes: OAuth scopes. Defaults to ["sheets", "drive_file"].
        """
        # Need drive_file scope to create spreadsheets
        self._scopes = scopes or ["sheets", "drive_file"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None
        self._drive_service: Any = None

    def _get_service(self) -> Any:
        """Get or create Sheets API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Sheets API requires OAuth authorization. "
                    "Run 'auth-utils sheets auth' to authorize.",
                )
            self._service = self._auth.build_service("sheets", "v4")
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
    # Spreadsheets
    # =========================================================================

    def get_spreadsheet(self, spreadsheet_id: str) -> Spreadsheet | None:
        """Get a spreadsheet by ID.

        Args:
            spreadsheet_id: Google Sheets spreadsheet ID.

        Returns:
            Spreadsheet or None if not found.
        """
        service = self._get_service()
        try:
            result = service.spreadsheets().get(spreadsheetId=spreadsheet_id).execute()
            return self._parse_spreadsheet(result)
        except Exception:
            return None

    def create_spreadsheet(self, title: str, sheet_titles: list[str] | None = None) -> Spreadsheet:
        """Create a new spreadsheet.

        Args:
            title: Spreadsheet title.
            sheet_titles: List of sheet names (optional).

        Returns:
            Created Spreadsheet.
        """
        service = self._get_service()

        body: dict[str, Any] = {"properties": {"title": title}}

        if sheet_titles:
            body["sheets"] = [{"properties": {"title": name}} for name in sheet_titles]

        result = service.spreadsheets().create(body=body).execute()
        return self._parse_spreadsheet(result)

    def delete_spreadsheet(self, spreadsheet_id: str) -> bool:
        """Delete a spreadsheet.

        Args:
            spreadsheet_id: Spreadsheet ID.

        Returns:
            True if deleted successfully.
        """
        drive_service = self._get_drive_service()
        try:
            drive_service.files().delete(fileId=spreadsheet_id).execute()
            return True
        except Exception:
            return False

    # =========================================================================
    # Reading Data
    # =========================================================================

    def read_range(
        self,
        spreadsheet_id: str,
        range_notation: str,
        value_render_option: str = "FORMATTED_VALUE",
    ) -> list[list[Any]]:
        """Read values from a range.

        Args:
            spreadsheet_id: Spreadsheet ID.
            range_notation: A1 notation (e.g., "Sheet1!A1:C10").
            value_render_option: How to render values ("FORMATTED_VALUE", "UNFORMATTED_VALUE", "FORMULA").

        Returns:
            2D list of cell values.
        """
        service = self._get_service()
        try:
            result = (
                service.spreadsheets()
                .values()
                .get(
                    spreadsheetId=spreadsheet_id,
                    range=range_notation,
                    valueRenderOption=value_render_option,
                )
                .execute()
            )
            return result.get("values", [])
        except Exception:
            return []

    def read_cell(self, spreadsheet_id: str, cell: str) -> Any:
        """Read a single cell value.

        Args:
            spreadsheet_id: Spreadsheet ID.
            cell: Cell in A1 notation (e.g., "Sheet1!A1").

        Returns:
            Cell value or None.
        """
        values = self.read_range(spreadsheet_id, cell)
        if values and values[0]:
            return values[0][0]
        return None

    # =========================================================================
    # Writing Data
    # =========================================================================

    def write_range(
        self,
        spreadsheet_id: str,
        range_notation: str,
        values: list[list[Any]],
        value_input_option: str = "USER_ENTERED",
    ) -> int:
        """Write values to a range.

        Args:
            spreadsheet_id: Spreadsheet ID.
            range_notation: A1 notation (e.g., "Sheet1!A1").
            values: 2D list of values to write.
            value_input_option: How to interpret input ("RAW" or "USER_ENTERED").

        Returns:
            Number of cells updated.
        """
        service = self._get_service()
        try:
            result = (
                service.spreadsheets()
                .values()
                .update(
                    spreadsheetId=spreadsheet_id,
                    range=range_notation,
                    valueInputOption=value_input_option,
                    body={"values": values},
                )
                .execute()
            )
            return result.get("updatedCells", 0)
        except Exception:
            return 0

    def write_cell(
        self,
        spreadsheet_id: str,
        cell: str,
        value: Any,
        value_input_option: str = "USER_ENTERED",
    ) -> bool:
        """Write a single cell value.

        Args:
            spreadsheet_id: Spreadsheet ID.
            cell: Cell in A1 notation (e.g., "Sheet1!A1").
            value: Value to write.
            value_input_option: How to interpret input.

        Returns:
            True if successful.
        """
        return self.write_range(spreadsheet_id, cell, [[value]], value_input_option) > 0

    def append_rows(
        self,
        spreadsheet_id: str,
        sheet_name: str,
        values: list[list[Any]],
        value_input_option: str = "USER_ENTERED",
    ) -> int:
        """Append rows to the end of a sheet.

        Args:
            spreadsheet_id: Spreadsheet ID.
            sheet_name: Name of the sheet.
            values: 2D list of rows to append.
            value_input_option: How to interpret input.

        Returns:
            Number of rows appended.
        """
        service = self._get_service()
        try:
            result = (
                service.spreadsheets()
                .values()
                .append(
                    spreadsheetId=spreadsheet_id,
                    range=f"{sheet_name}!A1",
                    valueInputOption=value_input_option,
                    insertDataOption="INSERT_ROWS",
                    body={"values": values},
                )
                .execute()
            )
            updates = result.get("updates", {})
            return updates.get("updatedRows", 0)
        except Exception:
            return 0

    def clear_range(self, spreadsheet_id: str, range_notation: str) -> bool:
        """Clear values from a range.

        Args:
            spreadsheet_id: Spreadsheet ID.
            range_notation: A1 notation (e.g., "Sheet1!A1:C10").

        Returns:
            True if successful.
        """
        service = self._get_service()
        try:
            service.spreadsheets().values().clear(
                spreadsheetId=spreadsheet_id, range=range_notation
            ).execute()
            return True
        except Exception:
            return False

    # =========================================================================
    # Sheet Management
    # =========================================================================

    def add_sheet(self, spreadsheet_id: str, title: str) -> Sheet | None:
        """Add a new sheet to a spreadsheet.

        Args:
            spreadsheet_id: Spreadsheet ID.
            title: New sheet title.

        Returns:
            Created Sheet or None if failed.
        """
        service = self._get_service()
        try:
            result = (
                service.spreadsheets()
                .batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body={"requests": [{"addSheet": {"properties": {"title": title}}}]},
                )
                .execute()
            )
            replies = result.get("replies", [])
            if replies and "addSheet" in replies[0]:
                props = replies[0]["addSheet"]["properties"]
                return Sheet(
                    id=props["sheetId"],
                    title=props["title"],
                    index=props["index"],
                )
            return None
        except Exception:
            return None

    def delete_sheet(self, spreadsheet_id: str, sheet_id: int) -> bool:
        """Delete a sheet from a spreadsheet.

        Args:
            spreadsheet_id: Spreadsheet ID.
            sheet_id: Sheet ID (not title).

        Returns:
            True if deleted successfully.
        """
        service = self._get_service()
        try:
            service.spreadsheets().batchUpdate(
                spreadsheetId=spreadsheet_id,
                body={"requests": [{"deleteSheet": {"sheetId": sheet_id}}]},
            ).execute()
            return True
        except Exception:
            return False

    def _parse_spreadsheet(self, data: dict) -> Spreadsheet:
        """Parse spreadsheet from API response."""
        sheets = []
        for sheet_data in data.get("sheets", []):
            props = sheet_data.get("properties", {})
            grid_props = props.get("gridProperties", {})
            sheets.append(
                Sheet(
                    id=props.get("sheetId", 0),
                    title=props.get("title", ""),
                    index=props.get("index", 0),
                    row_count=grid_props.get("rowCount", 1000),
                    column_count=grid_props.get("columnCount", 26),
                )
            )

        return Spreadsheet(
            id=data["spreadsheetId"],
            title=data.get("properties", {}).get("title", ""),
            sheets=sheets,
            url=data.get("spreadsheetUrl"),
        )
