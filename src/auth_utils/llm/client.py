"""
Unified LLM client for multi-provider support.
"""

import asyncio
from collections.abc import Sequence

from auth_utils.llm.exceptions import LLMError
from auth_utils.llm.models import LLMResponse, Message, Provider
from auth_utils.llm.providers.anthropic import AnthropicProvider
from auth_utils.llm.providers.base import BaseLLMProvider
from auth_utils.llm.providers.google import GoogleProvider
from auth_utils.llm.providers.openai import OpenAIProvider

# Provider registry
PROVIDERS: dict[Provider, type[BaseLLMProvider]] = {
    "claude": AnthropicProvider,
    "gemini": GoogleProvider,
    "chatgpt": OpenAIProvider,
}


class LLMClient:
    """
    Unified client for interacting with multiple LLM providers.

    Supports Claude (Anthropic), Gemini (Google), and ChatGPT (OpenAI).

    Example:
        >>> client = LLMClient(provider="claude")
        >>> response = await client.chat([Message(role="user", content="Hello!")])
        >>> print(response.content)

        # Parallel execution across all providers
        >>> responses = await LLMClient.parallel_chat(
        ...     messages=[Message(role="user", content="Hello!")],
        ...     providers=["claude", "gemini", "chatgpt"]
        ... )
    """

    def __init__(
        self,
        provider: Provider,
        model: str,
        api_key: str | None = None,
    ):
        """
        Initialize the LLM client.

        Args:
            provider: The LLM provider to use ("claude", "gemini", or "chatgpt").
            model: Model identifier (required). Each repo should specify its own models.
            api_key: Optional API key. If None, reads from environment variable.

        Raises:
            ValueError: If provider is not supported.
            AuthenticationError: If API key is not found.
        """
        if provider not in PROVIDERS:
            raise ValueError(
                f"Unknown provider: {provider}. Supported providers: {list(PROVIDERS.keys())}"
            )

        provider_class = PROVIDERS[provider]
        self._provider: BaseLLMProvider = provider_class(model=model, api_key=api_key)
        self._provider_name = provider

    @property
    def provider(self) -> Provider:
        """The current provider name."""
        return self._provider_name

    @property
    def model(self) -> str:
        """The current model identifier."""
        return self._provider.model

    async def chat(
        self,
        messages: Sequence[Message | dict],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> LLMResponse:
        """
        Send a chat completion request.

        Args:
            messages: List of conversation messages (Message objects or dicts).
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature (0-1).
            **kwargs: Provider-specific parameters.

        Returns:
            LLMResponse with content, model, provider, and usage stats.

        Raises:
            AuthenticationError: If API key is invalid.
            RateLimitError: If rate limit is exceeded.
            APIError: For other API errors.
        """
        # Convert dicts to Message objects if needed
        normalized_messages = [
            msg if isinstance(msg, Message) else Message(**msg) for msg in messages
        ]

        return await self._provider.chat(
            messages=normalized_messages,
            max_tokens=max_tokens,
            temperature=temperature,
            **kwargs,
        )

    @classmethod
    async def parallel_chat(
        cls,
        messages: Sequence[Message | dict],
        models: dict[Provider, str],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> dict[Provider, LLMResponse | LLMError]:
        """
        Send the same prompt to multiple providers in parallel.

        Args:
            messages: List of conversation messages.
            models: Dictionary mapping providers to model identifiers.
            max_tokens: Maximum tokens in response.
            temperature: Sampling temperature.
            **kwargs: Provider-specific parameters.

        Returns:
            Dictionary mapping provider names to responses or errors.
            Successful responses are LLMResponse objects.
            Failed responses are LLMError objects (not raised).

        Example:
            >>> results = await LLMClient.parallel_chat(
            ...     messages=[Message(role="user", content="Hello!")],
            ...     models={
            ...         "claude": "claude-opus-4-5-20251101",
            ...         "gemini": "gemini-2.5-flash",
            ...         "chatgpt": "gpt-5.2",
            ...     }
            ... )
            >>> for provider, result in results.items():
            ...     if isinstance(result, LLMResponse):
            ...         print(f"{provider}: {result.content}")
            ...     else:
            ...         print(f"{provider} failed: {result}")
        """

        async def safe_chat(
            provider: Provider, model: str
        ) -> tuple[Provider, LLMResponse | LLMError]:
            """Chat with error capture instead of raising."""
            try:
                client = cls(provider=provider, model=model)
                response = await client.chat(
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs,
                )
                return provider, response
            except LLMError as e:
                return provider, e

        # Run all providers in parallel
        tasks = [safe_chat(provider, model) for provider, model in models.items()]
        results = await asyncio.gather(*tasks)

        return dict(results)

    @classmethod
    def get_available_providers(cls) -> list[Provider]:
        """Return list of available provider names."""
        return list(PROVIDERS.keys())

    @classmethod
    def get_configured_providers(cls) -> dict[Provider, bool]:
        """
        Check which providers have API keys configured.

        Returns:
            Dictionary mapping provider names to configuration status.
            True if the API key environment variable is set, False otherwise.

        Example:
            >>> status = LLMClient.get_configured_providers()
            >>> print(status)
            {'claude': True, 'gemini': False, 'chatgpt': True}
        """
        import os

        env_vars = {
            "claude": "ANTHROPIC_API_KEY",
            "gemini": "GOOGLE_API_KEY",
            "chatgpt": "OPENAI_API_KEY",
        }

        return {
            provider: bool(os.environ.get(env_var))
            for provider, env_var in env_vars.items()
        }
