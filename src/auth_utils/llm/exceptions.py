"""
Unified exceptions for LLM client errors.

Maps provider-specific exceptions to a common hierarchy.
"""

from typing import Any


class LLMError(Exception):
    """Base exception for all LLM errors."""

    def __init__(self, message: str, provider: str | None = None, original: Any = None):
        super().__init__(message)
        self.provider = provider
        self.original = original


class AuthenticationError(LLMError):
    """Invalid or missing API key."""

    pass


class RateLimitError(LLMError):
    """Rate limit exceeded."""

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        original: Any = None,
        retry_after: float | None = None,
    ):
        super().__init__(message, provider, original)
        self.retry_after = retry_after


class APIError(LLMError):
    """General API error from provider."""

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        original: Any = None,
        status_code: int | None = None,
    ):
        super().__init__(message, provider, original)
        self.status_code = status_code
