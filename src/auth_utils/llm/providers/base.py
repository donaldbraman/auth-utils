"""
Abstract base class for LLM providers.
"""

from abc import ABC, abstractmethod
from typing import Self

from auth_utils.llm.models import LLMResponse, Message


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    provider_name: str

    def __init__(self, model: str, api_key: str | None = None):
        """
        Initialize the provider.

        Args:
            model: Model identifier (required).
            api_key: API key. If None, reads from environment variable.
        """
        self.model = model
        self.api_key = api_key

    @abstractmethod
    async def chat(
        self,
        messages: list[Message],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> LLMResponse:
        """
        Send a chat completion request.

        Args:
            messages: List of conversation messages.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0-1).
            **kwargs: Provider-specific parameters.

        Returns:
            LLMResponse with content and metadata.

        Raises:
            AuthenticationError: If API key is invalid or missing.
            RateLimitError: If rate limit is exceeded.
            APIError: For other API errors.
        """
        pass

    async def close(self) -> None:  # noqa: B027
        """Close the provider's HTTP client and release resources."""
        pass

    async def __aenter__(self) -> Self:
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager and close resources."""
        await self.close()

    def _format_messages(self, messages: list[Message]) -> list[dict]:
        """Convert Message objects to provider format."""
        return [{"role": m.role, "content": m.content} for m in messages]
