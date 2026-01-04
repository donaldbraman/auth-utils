"""
Google Gemini provider implementation.
"""

import os

from google import genai
from google.api_core import exceptions as google_exceptions
from google.genai import types

from auth_utils.llm.exceptions import APIError, AuthenticationError, RateLimitError
from auth_utils.llm.models import LLMResponse, Message, UsageStats
from auth_utils.llm.providers.base import BaseLLMProvider


class GoogleProvider(BaseLLMProvider):
    """Gemini provider using Google GenAI API."""

    provider_name = "gemini"

    def __init__(self, model: str, api_key: str | None = None):
        super().__init__(model, api_key)
        self._api_key = api_key or os.environ.get("GOOGLE_API_KEY")
        if not self._api_key:
            raise AuthenticationError(
                "GOOGLE_API_KEY not found in environment variables",
                provider=self.provider_name,
            )
        self._client = genai.Client(api_key=self._api_key)

    async def chat(
        self,
        messages: list[Message],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **_kwargs,
    ) -> LLMResponse:
        """Send a chat completion request to Gemini."""
        try:
            # Convert messages to Gemini format
            gemini_contents, system_instruction = self._convert_to_gemini_format(messages)

            # Configure generation
            config = types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
                system_instruction=system_instruction,
            )

            # Use async client for generate_content
            response = await self._client.aio.models.generate_content(
                model=self.model,
                contents=gemini_contents,
                config=config,
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

            # Check for truncation due to max tokens
            # Log warning if response was truncated (helps debug JSON parse failures)
            if response.candidates:
                finish_reason = response.candidates[0].finish_reason
                # finish_reason values: STOP, MAX_TOKENS, SAFETY, RECITATION, OTHER
                if finish_reason and str(finish_reason).upper() in ("MAX_TOKENS", "2"):
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning(
                        f"Gemini response truncated (finish_reason={finish_reason}). "
                        f"Response length: {len(content)} chars. "
                        f"Consider increasing max_tokens parameter."
                    )

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

    def _convert_to_gemini_format(
        self, messages: list[Message]
    ) -> tuple[list[types.Content], str | None]:
        """Convert messages to Gemini's content format.

        Returns:
            Tuple of (contents list, system_instruction string or None)
        """
        gemini_contents = []
        system_instruction = None

        for msg in messages:
            if msg.role == "system":
                # Gemini handles system as a separate instruction
                system_instruction = msg.content
            elif msg.role == "user":
                gemini_contents.append(
                    types.Content(role="user", parts=[types.Part.from_text(text=msg.content)])
                )
            elif msg.role == "assistant":
                gemini_contents.append(
                    types.Content(role="model", parts=[types.Part.from_text(text=msg.content)])
                )

        return gemini_contents, system_instruction

    async def close(self) -> None:
        """Close the Google GenAI client."""
        self._client.close()
