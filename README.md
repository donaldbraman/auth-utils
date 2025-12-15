# auth-utils

Shared authentication infrastructure for LLM providers and Google/Zotero APIs.

## Installation

```bash
# Install from GitHub
pip install git+https://github.com/donaldbraman/auth-utils.git

# Or with uv
uv add git+https://github.com/donaldbraman/auth-utils.git
```

## Features

- **LLM Providers**: Unified client for Claude, Gemini, and ChatGPT
- **Google OAuth**: OAuth 2.0 for Google Docs, Drive, Sheets, etc.
- **Zotero API**: Authentication for Zotero citation management

## LLM Client

### Configuration

Set API keys as environment variables:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GOOGLE_API_KEY="..."
```

### Usage

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

### Supported LLM Providers

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| `claude` | `ANTHROPIC_API_KEY` | `claude-opus-4-5-20251101` |
| `gemini` | `GOOGLE_API_KEY` | `gemini-2.5-flash` |
| `chatgpt` | `OPENAI_API_KEY` | `gpt-5.2` |

## Google OAuth

OAuth 2.0 authentication for Google APIs (Docs, Drive, Sheets, etc.).

### Setup

1. Create OAuth credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Download as `credentials.json`

### Usage

```python
from auth_utils.google import GoogleOAuth

# Initialize with desired scopes
auth = GoogleOAuth(scopes=["docs", "drive"])

# Check if already authorized
if not auth.is_authorized():
    # Start OAuth flow
    url = auth.get_authorization_url()
    print(f"Visit: {url}")

    # After user authorizes, complete the flow
    redirect_url = input("Paste redirect URL: ")
    auth.fetch_token(redirect_url)

# Build Google API services
docs_service = auth.build_service("docs", "v1")
drive_service = auth.build_service("drive", "v3")
```

### Available Scopes

| Scope Name | Permission |
|------------|------------|
| `docs` | Read/write Google Docs |
| `docs_readonly` | Read-only Google Docs |
| `drive` | Full Google Drive access |
| `drive_readonly` | Read-only Drive access |
| `drive_file` | Per-file Drive access |
| `sheets` | Read/write Google Sheets |
| `sheets_readonly` | Read-only Sheets |
| `gmail` | Modify Gmail |
| `calendar` | Full Calendar access |

## Zotero API

Authentication for Zotero citation management.

### Configuration

```bash
export ZOTERO_API_KEY="your-api-key"
export ZOTERO_LIBRARY_ID="12345"
export ZOTERO_LIBRARY_TYPE="user"  # or "group"
```

### Usage

```python
from auth_utils.zotero import ZoteroClient

# Initialize from environment variables
client = ZoteroClient()

# Or with explicit parameters
client = ZoteroClient(
    api_key="your-api-key",
    library_id="12345",
    library_type="user"
)

# Get items
items = client.get_items(limit=10)

# Search
results = client.search_items("machine learning")

# Get Zotero URIs for citations
uri = client.get_item_uri("ABC123")
# -> http://zotero.org/users/12345/items/ABC123
```

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
