# Integration Guide for Sibling Repos

This guide explains how to integrate auth-utils into sibling repositories (write-assist, cite-assist, pin-citer, etc.) for unified authentication and LLM access.

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

Set the environment variables for the services you need:

```bash
# LLM Providers
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export GOOGLE_API_KEY="..."              # Gemini
export OPENAI_API_KEY="sk-..."           # ChatGPT

# Zotero
export ZOTERO_API_KEY="..."
export ZOTERO_LIBRARY_ID="12345"
export ZOTERO_LIBRARY_TYPE="user"        # or "group"
export ZOTERO_USERNAME="your_username"   # optional, for web URLs
```

Or create a `.env` file (ensure it's in `.gitignore`).

---

## LLM Client

### Basic Usage

```python
from auth_utils.llm import LLMClient, Message, LLMResponse

# Model is required - each repo specifies its own
client = LLMClient(provider="claude", model="claude-sonnet-4-20250514")

# Send a message
response = await client.chat([
    Message(role="user", content="Hello!")
])

print(response.content)
print(f"Tokens: {response.usage.total_tokens}")
```

### Specifying Models

Each repo should specify its own models based on its needs:

```python
# write-assist: Premium models for quality
client = LLMClient(provider="claude", model="claude-opus-4-5-20251101")
client = LLMClient(provider="chatgpt", model="gpt-5.2")

# cite-assist: Fast/cheap models for throughput
client = LLMClient(provider="gemini", model="gemini-2.5-flash-lite")
```

### System Messages

```python
response = await client.chat([
    Message(role="system", content="You are a legal writing assistant."),
    Message(role="user", content="Draft an introduction about tort reform."),
])
```

### Parallel Execution

Run the same prompt across multiple providers simultaneously:

```python
from auth_utils.llm import LLMClient, Message, LLMResponse, LLMError

results = await LLMClient.parallel_chat(
    messages=[Message(role="user", content="Summarize Marbury v. Madison")],
    models={
        "claude": "claude-sonnet-4-20250514",
        "gemini": "gemini-2.5-flash",
        "chatgpt": "gpt-4o",
    },
)

for provider, result in results.items():
    if isinstance(result, LLMResponse):
        print(f"\n{provider}:\n{result.content}")
    else:
        print(f"\n{provider} error: {result}")
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
    response = await client.chat([Message(role="user", content="Hello")])
except AuthenticationError as e:
    print(f"Invalid API key for {e.provider}")
except RateLimitError as e:
    print(f"Rate limit exceeded, retry after {e.retry_after}s")
except APIError as e:
    print(f"API error ({e.status_code}): {e}")
```

### Available Models

| Provider | Model ID | Use Case |
|----------|----------|----------|
| Claude | `claude-opus-4-5-20251101` | Premium quality |
| Claude | `claude-sonnet-4-5-20250929` | Balanced |
| Claude | `claude-haiku-4-5-20251001` | Fast |
| Gemini | `gemini-2.5-flash` | Fast, good quality |
| Gemini | `gemini-2.5-flash-lite` | Ultra fast, lowest cost |
| ChatGPT | `gpt-5.2` | Latest flagship |

---

## Google OAuth

For accessing Google APIs (Docs, Drive, Sheets, Gmail, Calendar).

### Prerequisites

1. Create a project in [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the APIs you need (Docs, Drive, etc.)
3. Create OAuth 2.0 credentials (Desktop app)
4. Download `credentials.json` to your project root

### Basic Usage

```python
from auth_utils.google import GoogleOAuth

# Initialize with scopes you need
auth = GoogleOAuth(scopes=["docs", "drive"])

# Check if already authorized
if not auth.is_authorized():
    # Get authorization URL for user
    url = auth.get_authorization_url()
    print(f"Visit: {url}")

    # After user authorizes, get the redirect URL
    redirect_url = input("Paste redirect URL: ")
    auth.fetch_token(redirect_url)

# Build Google API service
docs_service = auth.build_service("docs", "v1")
drive_service = auth.build_service("drive", "v3")
```

### Available Scopes

Use friendly names or full URLs:

| Name | Scope URL |
|------|-----------|
| `docs` | `googleapis.com/auth/documents` |
| `docs_readonly` | `googleapis.com/auth/documents.readonly` |
| `drive` | `googleapis.com/auth/drive` |
| `drive_readonly` | `googleapis.com/auth/drive.readonly` |
| `drive_file` | `googleapis.com/auth/drive.file` |
| `sheets` | `googleapis.com/auth/spreadsheets` |
| `sheets_readonly` | `googleapis.com/auth/spreadsheets.readonly` |
| `gmail` | `googleapis.com/auth/gmail.modify` |
| `gmail_readonly` | `googleapis.com/auth/gmail.readonly` |
| `calendar` | `googleapis.com/auth/calendar` |
| `calendar_readonly` | `googleapis.com/auth/calendar.readonly` |

### Token Management

```python
# Get token info
info = auth.get_token_info()
print(f"Status: {info['status']}")
print(f"Scopes: {info['scopes']}")
print(f"Expires in: {info['expires_in']}")

# Revoke token
auth.revoke_token()
```

### Custom Paths

```python
auth = GoogleOAuth(
    scopes=["docs"],
    token_path="~/.config/myapp/token.json",
    credentials_path="~/.config/myapp/credentials.json",
)
```

### Error Handling

```python
from auth_utils.google import (
    GoogleOAuth,
    GoogleAuthError,
    CredentialsNotFoundError,
    TokenError,
    ScopeMismatchError,
)

try:
    auth = GoogleOAuth(scopes=["docs"])
    creds = auth.get_credentials()
except CredentialsNotFoundError:
    print("Missing credentials.json - download from Google Cloud Console")
except TokenError as e:
    print(f"Token error: {e}")
except ScopeMismatchError as e:
    print(f"Missing scopes: {e.missing_scopes}")
```

---

## Zotero Client

For accessing the Zotero API (items, collections, search).

### Getting API Credentials

1. Go to [Zotero Settings](https://www.zotero.org/settings/keys)
2. Create a new API key with the permissions you need
3. Note your user ID (shown on the keys page)

### Basic Usage

```python
from auth_utils.zotero import ZoteroClient

# Initialize (reads from env vars if not specified)
client = ZoteroClient(
    api_key="your-api-key",
    library_id="12345",
    library_type="user",  # or "group"
)

# Get recent items
items = client.get_items(limit=10)
for item in items:
    print(item["data"]["title"])

# Search items
results = client.search_items("machine learning")

# Get specific item
item = client.get_item("ABC12345")
```

### Environment Variables

Set these to avoid passing credentials in code:

```bash
export ZOTERO_API_KEY="your-api-key"
export ZOTERO_LIBRARY_ID="12345"
export ZOTERO_LIBRARY_TYPE="user"
export ZOTERO_USERNAME="your_username"  # optional
```

Then:

```python
client = ZoteroClient()  # Uses env vars
```

### Working with Collections

```python
# Get all collections
collections = client.get_collections()

# Get items in a collection
items = client.get_collection_items("COLLECTION_KEY")
```

### Getting URLs

```python
# Zotero URI (for linking)
uri = client.get_item_uri("ABC12345")
# -> http://zotero.org/users/12345/items/ABC12345

# Web URL (for viewing)
url = client.get_web_url("ABC12345")
# -> https://www.zotero.org/username/items/ABC12345
```

### Local Zotero Support

The client automatically tries local Zotero first (faster, no rate limits):

```python
# Disable local Zotero fallback
client = ZoteroClient(local_enabled=False)

# Check if local is available
if client.is_local_available:
    print("Using local Zotero")
```

### Error Handling

```python
from auth_utils.zotero import ZoteroClient, ZoteroAuthError, ZoteroAPIError

try:
    client = ZoteroClient()
    items = client.get_items()
except ZoteroAuthError as e:
    print(f"Authentication failed: {e}")
except ZoteroAPIError as e:
    print(f"API error ({e.status_code}): {e}")
```

### Context Manager

```python
with ZoteroClient() as client:
    items = client.get_items()
# Client automatically closed
```

---

## Re-export Pattern

For cleaner imports in your repo:

```python
# src/your_repo/auth/__init__.py
from auth_utils.llm import (
    LLMClient,
    Message,
    LLMResponse,
    AuthenticationError,
    RateLimitError,
    APIError,
)
from auth_utils.google import GoogleOAuth, GoogleAuthError
from auth_utils.zotero import ZoteroClient, ZoteroAuthError

__all__ = [
    "LLMClient",
    "Message",
    "LLMResponse",
    "AuthenticationError",
    "RateLimitError",
    "APIError",
    "GoogleOAuth",
    "GoogleAuthError",
    "ZoteroClient",
    "ZoteroAuthError",
]
```

Then import locally:

```python
from your_repo.auth import LLMClient, GoogleOAuth, ZoteroClient
```

---

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
