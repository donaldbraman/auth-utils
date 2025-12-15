"""Zotero authentication exceptions."""


class ZoteroAuthError(Exception):
    """Base exception for Zotero authentication errors."""

    pass


class ZoteroAPIError(ZoteroAuthError):
    """Raised when Zotero API returns an error."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)
