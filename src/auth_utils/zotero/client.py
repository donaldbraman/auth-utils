"""Zotero API client with authentication.

Provides authenticated access to both the Zotero Web API and local Zotero instance.
"""

import logging
import os
from typing import Any

import httpx

from auth_utils.zotero.exceptions import ZoteroAPIError, ZoteroAuthError

logger = logging.getLogger(__name__)


class ZoteroClient:
    """Zotero API client with authentication.

    Supports both cloud API (api.zotero.org) and local Zotero instance.

    Example:
        >>> client = ZoteroClient(
        ...     api_key="your-api-key",
        ...     library_id="12345",
        ...     library_type="user"
        ... )
        >>> items = client.get_items(limit=10)
    """

    CLOUD_BASE_URL = "https://api.zotero.org"
    LOCAL_BASE_URL = "http://localhost:23119/api"

    def __init__(
        self,
        api_key: str | None = None,
        library_id: str | None = None,
        library_type: str | None = None,
        username: str | None = None,
        local_enabled: bool = True,
        local_port: int = 23119,
    ):
        """Initialize Zotero client.

        Args:
            api_key: Zotero API key. If None, reads from ZOTERO_API_KEY env var.
            library_id: Library ID (user ID or group ID). If None, reads from ZOTERO_LIBRARY_ID.
            library_type: "user" or "group". If None, reads from ZOTERO_LIBRARY_TYPE (default: "user").
            username: Zotero username for generating web URLs.
            local_enabled: Whether to try local Zotero instance first.
            local_port: Port for local Zotero API.
        """
        self.api_key = api_key or os.environ.get("ZOTERO_API_KEY")
        self.library_id = library_id or os.environ.get("ZOTERO_LIBRARY_ID")
        self.library_type = library_type or os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
        self.username = username or os.environ.get("ZOTERO_USERNAME")
        self.local_enabled = local_enabled
        self.local_port = local_port

        if not self.library_id:
            raise ZoteroAuthError(
                "Zotero library_id is required. "
                "Set ZOTERO_LIBRARY_ID env var or pass library_id parameter."
            )

        self._client = httpx.Client(timeout=30.0)
        self._local_available: bool | None = None

    @property
    def cloud_url(self) -> str:
        """Get the base URL for cloud API requests."""
        if self.library_type == "group":
            return f"{self.CLOUD_BASE_URL}/groups/{self.library_id}"
        return f"{self.CLOUD_BASE_URL}/users/{self.library_id}"

    @property
    def local_url(self) -> str:
        """Get the base URL for local API requests."""
        return f"http://localhost:{self.local_port}/api"

    @property
    def is_local_available(self) -> bool:
        """Check if local Zotero instance is available."""
        if self._local_available is None:
            self._local_available = self._check_local_available()
        return self._local_available

    def _check_local_available(self) -> bool:
        """Check if local Zotero is running."""
        if not self.local_enabled:
            return False

        try:
            response = self._client.get(
                f"{self.local_url}/users/{self.library_id}/items",
                params={"limit": 1},
                timeout=2.0,
            )
            return response.status_code == 200
        except Exception:
            return False

    def _get_headers(self) -> dict[str, str]:
        """Get headers for API requests."""
        headers = {
            "Zotero-API-Version": "3",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        prefer_local: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """Make an authenticated API request.

        Args:
            method: HTTP method.
            endpoint: API endpoint (e.g., "/items").
            params: Query parameters.
            json: JSON body for POST/PUT.
            prefer_local: Try local Zotero first if available.

        Returns:
            API response data.

        Raises:
            ZoteroAPIError: If the API returns an error.
        """
        # Try local first if enabled and available
        if prefer_local and self.is_local_available:
            try:
                url = f"{self.local_url}/users/{self.library_id}{endpoint}"
                response = self._client.request(method, url, params=params, json=json, timeout=10.0)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                logger.debug(f"Local Zotero request failed, falling back to cloud: {e}")

        # Fall back to cloud API
        url = f"{self.cloud_url}{endpoint}"
        headers = self._get_headers()

        try:
            response = self._client.request(method, url, headers=headers, params=params, json=json)
        except httpx.HTTPError as e:
            raise ZoteroAPIError(f"Request failed: {e}") from e

        if response.status_code == 401:
            raise ZoteroAuthError("Invalid Zotero API key")
        elif response.status_code == 403:
            raise ZoteroAuthError("Access denied to this library")
        elif response.status_code >= 400:
            raise ZoteroAPIError(
                f"API error: {response.text}",
                status_code=response.status_code,
            )

        return response.json()

    def get_items(
        self,
        limit: int = 100,
        start: int = 0,
        sort: str = "dateModified",
        direction: str = "desc",
        item_type: str | None = None,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """Get items from the library.

        Args:
            limit: Maximum items to return.
            start: Offset for pagination.
            sort: Sort field.
            direction: Sort direction ("asc" or "desc").
            item_type: Filter by item type.
            **kwargs: Additional query parameters.

        Returns:
            List of item data.
        """
        params = {
            "limit": limit,
            "start": start,
            "sort": sort,
            "direction": direction,
            **kwargs,
        }
        if item_type:
            params["itemType"] = item_type

        return self._request("GET", "/items", params=params)

    def get_item(self, item_key: str) -> dict[str, Any]:
        """Get a specific item by key.

        Args:
            item_key: Zotero item key.

        Returns:
            Item data.
        """
        return self._request("GET", f"/items/{item_key}")

    def search_items(self, query: str, limit: int = 25) -> list[dict[str, Any]]:
        """Search for items.

        Args:
            query: Search query.
            limit: Maximum results.

        Returns:
            List of matching items.
        """
        return self._request("GET", "/items", params={"q": query, "limit": limit})

    def get_collections(self) -> list[dict[str, Any]]:
        """Get all collections in the library."""
        return self._request("GET", "/collections")

    def get_collection_items(self, collection_key: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get items in a specific collection.

        Args:
            collection_key: Zotero collection key.
            limit: Maximum items to return.

        Returns:
            List of items in the collection.
        """
        return self._request("GET", f"/collections/{collection_key}/items", params={"limit": limit})

    def get_item_uri(self, item_key: str) -> str:
        """Get the Zotero URI for an item.

        Args:
            item_key: Zotero item key.

        Returns:
            Zotero URI (e.g., http://zotero.org/users/12345/items/ABC123).
        """
        if self.library_type == "group":
            return f"http://zotero.org/groups/{self.library_id}/items/{item_key}"
        return f"http://zotero.org/users/{self.library_id}/items/{item_key}"

    def get_web_url(self, item_key: str) -> str:
        """Get the web URL for viewing an item.

        Args:
            item_key: Zotero item key.

        Returns:
            Web URL for the item.
        """
        if self.library_type == "group":
            return f"https://www.zotero.org/groups/{self.library_id}/items/{item_key}"
        if self.username:
            return f"https://www.zotero.org/{self.username}/items/{item_key}"
        return f"https://www.zotero.org/users/{self.library_id}/items/{item_key}"

    def close(self):
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
