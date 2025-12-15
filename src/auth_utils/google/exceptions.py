"""Google authentication exceptions."""


class GoogleAuthError(Exception):
    """Base exception for Google authentication errors."""

    pass


class CredentialsNotFoundError(GoogleAuthError):
    """Raised when OAuth credentials file is not found."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(
            f"Credentials file not found at {path}. "
            "Please download OAuth credentials from Google Cloud Console."
        )


class TokenError(GoogleAuthError):
    """Raised when there's an issue with the OAuth token."""

    pass


class ScopeMismatchError(GoogleAuthError):
    """Raised when token scopes don't match required scopes."""

    def __init__(self, missing_scopes: set[str]):
        self.missing_scopes = missing_scopes
        super().__init__(f"Token missing required scopes: {missing_scopes}")
