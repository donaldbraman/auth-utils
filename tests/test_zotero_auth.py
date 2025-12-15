"""Tests for Zotero authentication."""

import os
from unittest.mock import patch

import pytest

from auth_utils.zotero import ZoteroAuthError, ZoteroClient


class TestZoteroClientBasics:
    """Test basic ZoteroClient functionality."""

    def test_requires_library_id(self):
        """Should raise error when library_id is not provided."""
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(ZoteroAuthError, match="library_id is required"),
        ):
            ZoteroClient(library_id=None, api_key="test-key")

    def test_init_with_params(self):
        """Should initialize with explicit parameters."""
        client = ZoteroClient(
            api_key="test-api-key",
            library_id="12345",
            library_type="user",
            username="testuser",
        )
        assert client.api_key == "test-api-key"
        assert client.library_id == "12345"
        assert client.library_type == "user"
        assert client.username == "testuser"

    def test_init_from_env(self):
        """Should read configuration from environment variables."""
        env = {
            "ZOTERO_API_KEY": "env-api-key",
            "ZOTERO_LIBRARY_ID": "67890",
            "ZOTERO_LIBRARY_TYPE": "group",
            "ZOTERO_USERNAME": "envuser",
        }
        with patch.dict(os.environ, env):
            client = ZoteroClient()
            assert client.api_key == "env-api-key"
            assert client.library_id == "67890"
            assert client.library_type == "group"
            assert client.username == "envuser"

    def test_cloud_url_user_library(self):
        """Should generate correct cloud URL for user library."""
        client = ZoteroClient(library_id="12345", library_type="user")
        assert client.cloud_url == "https://api.zotero.org/users/12345"

    def test_cloud_url_group_library(self):
        """Should generate correct cloud URL for group library."""
        client = ZoteroClient(library_id="67890", library_type="group")
        assert client.cloud_url == "https://api.zotero.org/groups/67890"

    def test_local_url(self):
        """Should generate correct local URL."""
        client = ZoteroClient(library_id="12345", local_port=23119)
        assert client.local_url == "http://localhost:23119/api"

    def test_item_uri_user(self):
        """Should generate correct Zotero URI for user library."""
        client = ZoteroClient(library_id="12345", library_type="user")
        uri = client.get_item_uri("ABC123")
        assert uri == "http://zotero.org/users/12345/items/ABC123"

    def test_item_uri_group(self):
        """Should generate correct Zotero URI for group library."""
        client = ZoteroClient(library_id="67890", library_type="group")
        uri = client.get_item_uri("DEF456")
        assert uri == "http://zotero.org/groups/67890/items/DEF456"

    def test_web_url_with_username(self):
        """Should generate web URL using username when available."""
        client = ZoteroClient(
            library_id="12345",
            library_type="user",
            username="testuser",
        )
        url = client.get_web_url("ABC123")
        assert url == "https://www.zotero.org/testuser/items/ABC123"

    def test_web_url_group(self):
        """Should generate web URL for group library."""
        client = ZoteroClient(library_id="67890", library_type="group")
        url = client.get_web_url("DEF456")
        assert url == "https://www.zotero.org/groups/67890/items/DEF456"

    def test_context_manager(self):
        """Should work as context manager."""
        with ZoteroClient(library_id="12345") as client:
            assert client.library_id == "12345"


class TestZoteroClientHeaders:
    """Test header generation."""

    def test_headers_with_api_key(self):
        """Should include authorization header when API key is set."""
        client = ZoteroClient(library_id="12345", api_key="test-key")
        headers = client._get_headers()
        assert headers["Authorization"] == "Bearer test-key"
        assert headers["Zotero-API-Version"] == "3"

    def test_headers_without_api_key(self):
        """Should not include authorization when no API key."""
        client = ZoteroClient(library_id="12345", api_key=None)
        headers = client._get_headers()
        assert "Authorization" not in headers
        assert headers["Zotero-API-Version"] == "3"


# Integration tests - skip if no credentials
skip_no_zotero = pytest.mark.skipif(
    not os.environ.get("ZOTERO_API_KEY") or not os.environ.get("ZOTERO_LIBRARY_ID"),
    reason="ZOTERO_API_KEY and ZOTERO_LIBRARY_ID required",
)


@skip_no_zotero
class TestZoteroIntegration:
    """Integration tests for Zotero API (requires credentials)."""

    @pytest.fixture
    def client(self):
        """Create a client from environment variables."""
        return ZoteroClient()

    def test_get_items(self, client):
        """Should retrieve items from library."""
        items = client.get_items(limit=5)
        assert isinstance(items, list)

    def test_get_collections(self, client):
        """Should retrieve collections from library."""
        collections = client.get_collections()
        assert isinstance(collections, list)
