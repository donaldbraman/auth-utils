"""
Anthropic Claude provider implementation.
"""

import os

from anthropic import (
    APIConnectionError as AnthropicConnectionError,
)
from anthropic import (
    APIStatusError as AnthropicStatusError,
)
from anthropic import AsyncAnthropic
from anthropic import (
    AuthenticationError as AnthropicAuthError,
)
from anthropic import (
    RateLimitError as AnthropicRateLimitError,
)

from auth_utils.llm.exceptions import APIError, AuthenticationError, RateLimitError
from auth_utils.llm.models import LLMResponse, Message, UsageStats
from auth_utils.llm.providers.base import BaseLLMProvider


class AnthropicProvider(BaseLLMProvider):
    """Claude provider using Anthropic API."""

    provider_name = "claude"
    default_model = "claude-opus-4-5-20251101"

    def __init__(self, model: str | None = None, api_key: str | None = None):
        super().__init__(model, api_key)
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "ANTHROPIC_API_KEY not found in environment variables",
                provider=self.provider_name,
            )
        self._client = AsyncAnthropic(api_key=self._api_key)

    async def chat(
        self,
        messages: list[Message],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to Claude."""
        try:
            # Separate system message from conversation
            system_content = None
            conversation = []

            for msg in messages:
                if msg.role == "system":
                    system_content = msg.content
                else:
                    conversation.append({"role": msg.role, "content": msg.content})

            # Build request parameters
            params = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": conversation,
                "temperature": temperature,
            }

            if system_content:
                params["system"] = system_content

            # Add any extra kwargs
            params.update(kwargs)

            response = await self._client.messages.create(**params)

            return LLMResponse(
                content=response.content[0].text,
                model=response.model,
                provider=self.provider_name,
                usage=UsageStats(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                ),
                raw_response=response,
            )

        except AnthropicAuthError as e:
            raise AuthenticationError(
                f"Anthropic authentication failed: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except AnthropicRateLimitError as e:
            raise RateLimitError(
                f"Anthropic rate limit exceeded: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except AnthropicConnectionError as e:
            raise APIError(
                f"Anthropic connection error: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except AnthropicStatusError as e:
            raise APIError(
                f"Anthropic API error: {e}",
                provider=self.provider_name,
                original=e,
                status_code=e.status_code,
            ) from e
