# auth-utils

Shared LLM authentication infrastructure for multi-provider support (Claude, Gemini, ChatGPT).

## Installation

```bash
# Install from GitHub
pip install git+https://github.com/donaldbraman/auth-utils.git

# Or with uv
uv add git+https://github.com/donaldbraman/auth-utils.git
```

## Configuration

Set API keys as environment variables:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GOOGLE_API_KEY="..."
```

## Usage

### Single Provider

```python
from auth_utils.llm import LLMClient, Message

# Create a client for a specific provider
client = LLMClient(provider="claude")  # or "gemini" or "chatgpt"

# Send a message
response = await client.chat([
    Message(role="user", content="Hello!")
])

print(response.content)
print(f"Tokens used: {response.usage.total_tokens}")
```

### Parallel Execution

```python
from auth_utils.llm import LLMClient, Message, LLMResponse

# Send same prompt to all providers in parallel
results = await LLMClient.parallel_chat(
    messages=[Message(role="user", content="Hello!")],
    providers=["claude", "gemini", "chatgpt"]
)

for provider, result in results.items():
    if isinstance(result, LLMResponse):
        print(f"{provider}: {result.content}")
    else:
        print(f"{provider} error: {result}")
```

### Error Handling

```python
from auth_utils.llm import (
    LLMClient,
    AuthenticationError,
    RateLimitError,
    APIError,
)

try:
    client = LLMClient(provider="claude")
    response = await client.chat([{"role": "user", "content": "Hello"}])
except AuthenticationError as e:
    print(f"Invalid API key for {e.provider}")
except RateLimitError as e:
    print(f"Rate limit exceeded: retry after {e.retry_after}s")
except APIError as e:
    print(f"API error ({e.status_code}): {e}")
```

## Supported Providers

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| `claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-5-20251101` |
| `gemini` | `GOOGLE_API_KEY` | `gemini-2.5-flash` |
| `chatgpt` | `OPENAI_API_KEY` | `gpt-5.2` |

## Development

```bash
# Clone the repo
git clone https://github.com/donaldbraman/auth-utils.git
cd auth-utils

# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Format and lint
uv run ruff check --fix
uv run ruff format
```

## License

MIT
