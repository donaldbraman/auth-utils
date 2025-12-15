"""
Integration tests for the LLM client.

These tests make REAL API calls - no mocks.
Requires valid API keys in environment variables:
- ANTHROPIC_API_KEY
- GOOGLE_API_KEY
- OPENAI_API_KEY
"""

import os

import pytest

from auth_utils.llm import (
    APIError,
    AuthenticationError,
    LLMClient,
    LLMResponse,
    Message,
)

# Cheapest models for testing - each repo defines its own for production
TEST_MODELS = {
    "claude": "claude-haiku-4-5-20251001",
    "gemini": "gemini-2.5-flash-lite",
    "chatgpt": "gpt-4o-mini",
}


def has_api_key(env_var: str) -> bool:
    """Check if an API key is available."""
    return bool(os.environ.get(env_var))


# Skip markers for when API keys are not available
skip_no_anthropic = pytest.mark.skipif(
    not has_api_key("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set",
)
skip_no_google = pytest.mark.skipif(
    not has_api_key("GOOGLE_API_KEY"),
    reason="GOOGLE_API_KEY not set",
)
skip_no_openai = pytest.mark.skipif(
    not has_api_key("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set",
)
skip_no_all_keys = pytest.mark.skipif(
    not (
        has_api_key("ANTHROPIC_API_KEY")
        and has_api_key("GOOGLE_API_KEY")
        and has_api_key("OPENAI_API_KEY")
    ),
    reason="Not all API keys are set",
)


class TestLLMClientBasics:
    """Basic client functionality tests."""

    def test_get_available_providers(self):
        """Should return list of available providers."""
        providers = LLMClient.get_available_providers()
        assert "claude" in providers
        assert "gemini" in providers
        assert "chatgpt" in providers

    def test_invalid_provider_raises(self):
        """Should raise ValueError for unknown provider."""
        with pytest.raises(ValueError, match="Unknown provider"):
            LLMClient(provider="invalid", model="test")  # type: ignore

    def test_model_required(self):
        """Should raise TypeError when model not provided."""
        with pytest.raises(TypeError):
            LLMClient(provider="claude")  # type: ignore


@pytest.mark.asyncio
class TestClaudeIntegration:
    """Integration tests for Claude (Anthropic)."""

    @skip_no_anthropic
    async def test_simple_chat(self):
        """Should complete a simple chat request."""
        client = LLMClient(provider="claude", model=TEST_MODELS["claude"])
        response = await client.chat(
            messages=[Message(role="user", content="Say 'hello' and nothing else.")],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert response.provider == "claude"
        assert "claude" in response.model.lower()
        assert len(response.content) > 0
        assert "hello" in response.content.lower()
        assert response.usage.total_tokens > 0

    @skip_no_anthropic
    async def test_with_system_message(self):
        """Should handle system messages correctly."""
        client = LLMClient(provider="claude", model=TEST_MODELS["claude"])
        response = await client.chat(
            messages=[
                Message(role="system", content="You are a pirate. Always say 'Arrr'."),
                Message(role="user", content="Hello!"),
            ],
            max_tokens=100,
        )

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0

    @skip_no_anthropic
    async def test_dict_messages(self):
        """Should accept dict format messages."""
        client = LLMClient(provider="claude", model=TEST_MODELS["claude"])
        response = await client.chat(
            messages=[{"role": "user", "content": "Say 'test' and nothing else."}],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert "test" in response.content.lower()


@pytest.mark.asyncio
class TestGeminiIntegration:
    """Integration tests for Gemini (Google)."""

    @skip_no_google
    async def test_simple_chat(self):
        """Should complete a simple chat request."""
        client = LLMClient(provider="gemini", model=TEST_MODELS["gemini"])
        response = await client.chat(
            messages=[Message(role="user", content="Say 'hello' and nothing else.")],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert response.provider == "gemini"
        assert len(response.content) > 0
        assert "hello" in response.content.lower()

    @skip_no_google
    async def test_with_system_message(self):
        """Should handle system messages correctly."""
        client = LLMClient(provider="gemini", model=TEST_MODELS["gemini"])
        response = await client.chat(
            messages=[
                Message(role="system", content="Always respond in exactly 3 words."),
                Message(role="user", content="What is Python?"),
            ],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0


@pytest.mark.asyncio
class TestChatGPTIntegration:
    """Integration tests for ChatGPT (OpenAI)."""

    @skip_no_openai
    async def test_simple_chat(self):
        """Should complete a simple chat request."""
        client = LLMClient(provider="chatgpt", model=TEST_MODELS["chatgpt"])
        response = await client.chat(
            messages=[Message(role="user", content="Say 'hello' and nothing else.")],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert response.provider == "chatgpt"
        assert "gpt" in response.model.lower()
        assert len(response.content) > 0
        assert "hello" in response.content.lower()
        assert response.usage.total_tokens > 0

    @skip_no_openai
    async def test_with_system_message(self):
        """Should handle system messages correctly."""
        client = LLMClient(provider="chatgpt", model=TEST_MODELS["chatgpt"])
        response = await client.chat(
            messages=[
                Message(role="system", content="You respond only with 'OK'."),
                Message(role="user", content="Hello!"),
            ],
            max_tokens=50,
        )

        assert isinstance(response, LLMResponse)
        assert len(response.content) > 0


@pytest.mark.asyncio
class TestParallelExecution:
    """Tests for parallel multi-provider execution."""

    @skip_no_all_keys
    async def test_parallel_chat_all_providers(self):
        """Should execute chat on all providers in parallel."""
        messages = [Message(role="user", content="Say 'yes' and nothing else.")]

        results = await LLMClient.parallel_chat(
            messages=messages,
            models=TEST_MODELS,
            max_tokens=50,
        )

        assert len(results) == 3
        assert "claude" in results
        assert "gemini" in results
        assert "chatgpt" in results

        # Check each result
        for provider, result in results.items():
            if isinstance(result, LLMResponse):
                assert result.provider == provider
                assert len(result.content) > 0
                print(f"{provider}: {result.content[:50]}...")
            else:
                # If it's an error, print it for debugging
                print(f"{provider} error: {result}")

    @skip_no_anthropic
    async def test_parallel_chat_single_provider(self):
        """Should work with single provider."""
        messages = [Message(role="user", content="Say 'test'.")]

        results = await LLMClient.parallel_chat(
            messages=messages,
            models={"claude": TEST_MODELS["claude"]},
            max_tokens=50,
        )

        assert len(results) == 1
        assert "claude" in results
        assert isinstance(results["claude"], LLMResponse)


@pytest.mark.asyncio
class TestErrorHandling:
    """Tests for error handling."""

    async def test_missing_api_key_raises_auth_error(self):
        """Should raise AuthenticationError for missing API key."""
        # Temporarily unset the key
        original = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with pytest.raises(AuthenticationError):
                LLMClient(provider="claude", model=TEST_MODELS["claude"])
        finally:
            if original:
                os.environ["ANTHROPIC_API_KEY"] = original

    @skip_no_anthropic
    async def test_invalid_api_key_raises_auth_error(self):
        """Should raise AuthenticationError for invalid API key."""
        client = LLMClient(provider="claude", model=TEST_MODELS["claude"], api_key="invalid-key")
        with pytest.raises((AuthenticationError, APIError)):
            await client.chat(
                messages=[Message(role="user", content="Hello")],
                max_tokens=10,
            )
