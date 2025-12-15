# Integration Guide for Sibling Repos

This guide explains how to integrate auth-utils into sibling repositories (write-assist, cite-assist, etc.) for unified LLM access.

## Installation

Add auth-utils as a dependency in your `pyproject.toml`:

```toml
[project]
dependencies = [
    "auth-utils @ git+https://github.com/donaldbraman/auth-utils.git",
]

[tool.hatch.metadata]
allow-direct-references = true
```

Then install:

```bash
uv sync
```

## Environment Setup

Set API keys for the providers you need:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export GOOGLE_API_KEY="..."              # Gemini
export OPENAI_API_KEY="sk-..."           # ChatGPT
```

Or create a `.env` file (ensure it's in `.gitignore`):

```bash
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...
OPENAI_API_KEY=sk-...
```

## Basic Usage

### Import the Client

```python
from auth_utils.llm import LLMClient, Message, LLMResponse
```

### Single Provider

```python
# Use default model for provider
client = LLMClient(provider="claude")

# Or specify a model
client = LLMClient(provider="claude", model="claude-sonnet-4-5-20250929")

# Send a message
response = await client.chat([
    Message(role="user", content="Hello!")
])

print(response.content)
print(f"Tokens: {response.usage.total_tokens}")
```

### Specifying Models Per Repo

Each repo should specify its own models based on its needs:

```python
# write-assist: Uses premium models for quality
client = LLMClient(provider="claude", model="claude-opus-4-5-20251101")
client = LLMClient(provider="gemini", model="gemini-3-pro-preview")
client = LLMClient(provider="chatgpt", model="gpt-5.2")

# cite-assist: Uses fast/cheap models for high throughput
client = LLMClient(provider="gemini", model="gemini-2.5-flash-lite")
```

### System Messages

```python
response = await client.chat([
    Message(role="system", content="You are a legal writing assistant."),
    Message(role="user", content="Draft an introduction about tort reform."),
])
```

### Dict Format (Alternative)

```python
response = await client.chat([
    {"role": "system", "content": "You respond in formal academic style."},
    {"role": "user", "content": "Explain consideration in contract law."},
])
```

## Parallel Execution

Run the same prompt across multiple providers simultaneously:

```python
from auth_utils.llm import LLMClient, Message, LLMResponse, LLMError

results = await LLMClient.parallel_chat(
    messages=[Message(role="user", content="Summarize Marbury v. Madison")],
    providers=["claude", "gemini", "chatgpt"],
    max_tokens=500,
)

for provider, result in results.items():
    if isinstance(result, LLMResponse):
        print(f"\n{provider}:\n{result.content}")
    else:
        print(f"\n{provider} error: {result}")
```

## Error Handling

```python
from auth_utils.llm import (
    LLMClient,
    AuthenticationError,
    RateLimitError,
    APIError,
)

try:
    client = LLMClient(provider="claude")
    response = await client.chat([
        Message(role="user", content="Hello")
    ])
except AuthenticationError as e:
    print(f"Invalid API key for {e.provider}")
except RateLimitError as e:
    print(f"Rate limit exceeded, retry after {e.retry_after}s")
except APIError as e:
    print(f"API error ({e.status_code}): {e}")
```

## Available Models

### Claude (Anthropic)

| Model | API ID | Use Case |
|-------|--------|----------|
| Opus 4.5 | `claude-opus-4-5-20251101` | Premium quality, complex reasoning |
| Sonnet 4.5 | `claude-sonnet-4-5-20250929` | Balanced speed/quality |
| Haiku 4.5 | `claude-haiku-4-5-20251001` | Fast, cost-effective |

### Gemini (Google)

| Model | API ID | Use Case |
|-------|--------|----------|
| 3 Pro Preview | `gemini-3-pro-preview` | Most intelligent |
| 2.5 Flash | `gemini-2.5-flash` | Fast, good quality |
| 2.5 Flash Lite | `gemini-2.5-flash-lite` | Ultra fast, lowest cost |

### ChatGPT (OpenAI)

| Model | API ID | Use Case |
|-------|--------|----------|
| GPT-5.2 | `gpt-5.2` | Latest flagship |
| GPT-5.1 | `gpt-5.1` | Previous flagship |

## Re-export Pattern

For cleaner imports in your repo, create a local re-export module:

```python
# src/your_repo/llm/__init__.py
from auth_utils.llm import (
    LLMClient,
    Message,
    LLMResponse,
    UsageStats,
    LLMError,
    AuthenticationError,
    RateLimitError,
    APIError,
)

__all__ = [
    "LLMClient",
    "Message",
    "LLMResponse",
    "UsageStats",
    "LLMError",
    "AuthenticationError",
    "RateLimitError",
    "APIError",
]
```

Then import locally:

```python
from your_repo.llm import LLMClient, Message
```

## Response Structure

```python
@dataclass
class LLMResponse:
    content: str           # The generated text
    model: str             # Model that generated it
    provider: str          # "claude", "gemini", or "chatgpt"
    usage: UsageStats      # Token usage statistics
    raw_response: Any      # Provider's raw response object

@dataclass
class UsageStats:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens
```

## Testing

Integration tests require API keys. Tests skip gracefully without them:

```bash
# Run with keys set
export ANTHROPIC_API_KEY="..."
uv run pytest -v

# Tests will skip if keys are missing
uv run pytest -v  # Shows SKIPPED for integration tests
```

## Updating auth-utils

To pull the latest version:

```bash
uv sync --refresh-package auth-utils
```

Or update the lock file:

```bash
uv lock --refresh-package auth-utils
uv sync
```
