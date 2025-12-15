"""Tests for Google OAuth authentication."""

import json

import pytest

from auth_utils.google import (
    CredentialsNotFoundError,
    GoogleOAuth,
)
from auth_utils.google.oauth import SCOPES


class TestGoogleOAuthBasics:
    """Test basic GoogleOAuth functionality."""

    def test_scope_resolution(self):
        """Should resolve scope names to URLs."""
        with pytest.raises(CredentialsNotFoundError):
            # Will fail on credentials, but we can test scope resolution
            GoogleOAuth(scopes=["docs", "drive"])

    def test_unknown_scope_raises(self):
        """Should raise error for unknown scope names."""
        with pytest.raises(ValueError, match="Unknown scope"):
            GoogleOAuth(scopes=["unknown_scope"])

    def test_full_url_scopes_accepted(self):
        """Should accept full scope URLs."""
        with pytest.raises(CredentialsNotFoundError):
            GoogleOAuth(scopes=["https://www.googleapis.com/auth/documents"])

    def test_credentials_not_found(self):
        """Should raise error when credentials file is missing."""
        with pytest.raises(CredentialsNotFoundError):
            GoogleOAuth(credentials_path="nonexistent.json")

    def test_available_scopes(self):
        """Should have common Google scopes defined."""
        assert "docs" in SCOPES
        assert "drive" in SCOPES
        assert "sheets" in SCOPES
        assert "gmail" in SCOPES
        assert "calendar" in SCOPES


class TestGoogleOAuthWithCredentials:
    """Tests that require mock credentials."""

    @pytest.fixture
    def mock_credentials(self, tmp_path):
        """Create a mock credentials file."""
        creds = {
            "installed": {
                "client_id": "test-client-id.apps.googleusercontent.com",
                "client_secret": "test-client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost"],
            }
        }
        creds_path = tmp_path / "credentials.json"
        with open(creds_path, "w") as f:
            json.dump(creds, f)
        return creds_path

    @pytest.fixture
    def mock_token(self, tmp_path):
        """Create a mock token file."""
        token = {
            "token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-client-secret",
            "scopes": [
                "https://www.googleapis.com/auth/documents",
                "https://www.googleapis.com/auth/drive",
            ],
            "type": "Bearer",
            "expiry": "2099-01-01T00:00:00Z",
        }
        token_path = tmp_path / "token.json"
        with open(token_path, "w") as f:
            json.dump(token, f)
        return token_path

    def test_load_installed_credentials(self, mock_credentials, tmp_path):
        """Should load installed app credentials."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(tmp_path / "token.json"),
        )
        assert auth.client_id == "test-client-id.apps.googleusercontent.com"
        assert auth.client_secret == "test-client-secret"

    def test_load_web_credentials(self, tmp_path):
        """Should load web app credentials."""
        creds = {
            "web": {
                "client_id": "web-client-id.apps.googleusercontent.com",
                "client_secret": "web-client-secret",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        }
        creds_path = tmp_path / "credentials.json"
        with open(creds_path, "w") as f:
            json.dump(creds, f)

        auth = GoogleOAuth(
            credentials_path=str(creds_path),
            token_path=str(tmp_path / "token.json"),
        )
        assert auth.client_id == "web-client-id.apps.googleusercontent.com"

    def test_is_authorized_without_token(self, mock_credentials, tmp_path):
        """Should return False when no token exists."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(tmp_path / "token.json"),
        )
        assert auth.is_authorized() is False

    def test_is_authorized_with_valid_token(self, mock_credentials, mock_token):
        """Should return True when valid token exists."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(mock_token),
        )
        assert auth.is_authorized() is True

    def test_get_authorization_url(self, mock_credentials, tmp_path):
        """Should generate authorization URL."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(tmp_path / "token.json"),
        )
        url = auth.get_authorization_url()
        assert "accounts.google.com" in url
        assert "client_id=" in url
        assert "scope=" in url

    def test_get_token_info_no_token(self, mock_credentials, tmp_path):
        """Should return no_token status when no token exists."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(tmp_path / "token.json"),
        )
        info = auth.get_token_info()
        assert info["status"] == "no_token"

    def test_get_token_info_with_token(self, mock_credentials, mock_token):
        """Should return token info when token exists."""
        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(mock_token),
        )
        info = auth.get_token_info()
        assert info["status"] == "valid"
        assert info["has_refresh_token"] is True
        assert len(info["scopes"]) == 2

    def test_scope_validation_on_token_load(self, mock_credentials, tmp_path):
        """Should reject token with missing scopes."""
        # Token with only docs scope, but we require docs + drive
        token = {
            "token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "scopes": ["https://www.googleapis.com/auth/documents"],
            "expiry": "2099-01-01T00:00:00Z",
        }
        token_path = tmp_path / "token.json"
        with open(token_path, "w") as f:
            json.dump(token, f)

        auth = GoogleOAuth(
            credentials_path=str(mock_credentials),
            token_path=str(token_path),
            scopes=["docs", "drive"],  # Requires both
        )
        # Token should be rejected due to missing scopes
        assert auth.is_authorized() is False
