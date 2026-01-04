"""
OpenAI ChatGPT provider implementation.
"""

import os

from openai import (
    APIConnectionError as OpenAIConnectionError,
)
from openai import (
    APIStatusError as OpenAIStatusError,
)
from openai import AsyncOpenAI
from openai import (
    AuthenticationError as OpenAIAuthError,
)
from openai import (
    RateLimitError as OpenAIRateLimitError,
)

from auth_utils.llm.exceptions import APIError, AuthenticationError, RateLimitError
from auth_utils.llm.models import LLMResponse, Message, UsageStats
from auth_utils.llm.providers.base import BaseLLMProvider


class OpenAIProvider(BaseLLMProvider):
    """ChatGPT provider using OpenAI API."""

    provider_name = "chatgpt"

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model, api_key)
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "OPENAI_API_KEY not found in environment variables",
                provider=self.provider_name,
            )
        self._client = AsyncOpenAI(api_key=self._api_key)

    async def chat(
        self,
        messages: list[Message],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to ChatGPT."""
        try:
            formatted_messages = self._format_messages(messages)

            response = await self._client.chat.completions.create(
                model=self.model,
                messages=formatted_messages,
                max_completion_tokens=max_tokens,
                temperature=temperature,
                **kwargs,
            )

            # Extract usage stats
            usage = UsageStats()
            if response.usage:
                usage = UsageStats(
                    input_tokens=response.usage.prompt_tokens,
                    output_tokens=response.usage.completion_tokens,
                )

            return LLMResponse(
                content=response.choices[0].message.content or "",
                model=response.model,
                provider=self.provider_name,
                usage=usage,
                raw_response=response,
            )

        except OpenAIAuthError as e:
            raise AuthenticationError(
                f"OpenAI authentication failed: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except OpenAIRateLimitError as e:
            raise RateLimitError(
                f"OpenAI rate limit exceeded: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except OpenAIConnectionError as e:
            raise APIError(
                f"OpenAI connection error: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except OpenAIStatusError as e:
            raise APIError(
                f"OpenAI API error: {e}",
                provider=self.provider_name,
                original=e,
                status_code=e.status_code,
            ) from e

    async def close(self) -> None:
        """Close the OpenAI client."""
        await self._client.close()
