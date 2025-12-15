"""
Google Gemini provider implementation.
"""

import os

import google.generativeai as genai
from google.api_core import exceptions as google_exceptions

from auth_utils.llm.exceptions import APIError, AuthenticationError, RateLimitError
from auth_utils.llm.models import LLMResponse, Message, UsageStats
from auth_utils.llm.providers.base import BaseLLMProvider


class GoogleProvider(BaseLLMProvider):
    """Gemini provider using Google Generative AI API."""

    provider_name = "gemini"

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model, api_key)
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "GOOGLE_API_KEY not found in environment variables",
                provider=self.provider_name,
            )
        genai.configure(api_key=self._api_key)
        self._model = genai.GenerativeModel(self.model)

    async def chat(
        self,
        messages: list[Message],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to Gemini."""
        try:
            # Convert messages to Gemini format
            gemini_messages = self._convert_to_gemini_format(messages)

            # Configure generation
            generation_config = genai.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )

            # Gemini's generate_content_async for async support
            response = await self._model.generate_content_async(
                gemini_messages,
                generation_config=generation_config,
                **kwargs,
            )

            # Extract usage stats if available
            usage = UsageStats()
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage = UsageStats(
                    input_tokens=response.usage_metadata.prompt_token_count or 0,
                    output_tokens=response.usage_metadata.candidates_token_count or 0,
                )

            # Safely extract content - response.text can raise ValueError
            # if no parts are returned (e.g., MAX_TOKENS with no content)
            content = ""
            try:
                content = response.text
            except ValueError:
                # Try to extract from candidates directly
                if response.candidates and response.candidates[0].content.parts:
                    content = response.candidates[0].content.parts[0].text

            return LLMResponse(
                content=content,
                model=self.model,
                provider=self.provider_name,
                usage=usage,
                raw_response=response,
            )

        except google_exceptions.Unauthenticated as e:
            raise AuthenticationError(
                f"Google authentication failed: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except google_exceptions.ResourceExhausted as e:
            raise RateLimitError(
                f"Google rate limit exceeded: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except google_exceptions.GoogleAPIError as e:
            raise APIError(
                f"Google API error: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

        except Exception as e:
            # Catch any other exceptions from the SDK
            raise APIError(
                f"Google API error: {e}",
                provider=self.provider_name,
                original=e,
            ) from e

    def _convert_to_gemini_format(self, messages: list[Message]) -> list[dict]:
        """Convert messages to Gemini's content format."""
        gemini_contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                # Gemini handles system as a separate instruction
                system_instruction = msg.content
            elif msg.role == "user":
                gemini_contents.append({"role": "user", "parts": [msg.content]})
            elif msg.role == "assistant":
                gemini_contents.append({"role": "model", "parts": [msg.content]})

        # If there's a system instruction, prepend it to the first user message
        # or create a context message
        if system_instruction and gemini_contents:
            if gemini_contents[0]["role"] == "user":
                # Prepend system instruction to first user message
                gemini_contents[0]["parts"].insert(
                    0, f"System instruction: {system_instruction}\n\n"
                )
            else:
                # Insert as first user message
                gemini_contents.insert(
                    0,
                    {
                        "role": "user",
                        "parts": [f"System instruction: {system_instruction}"],
                    },
                )

        return gemini_contents
