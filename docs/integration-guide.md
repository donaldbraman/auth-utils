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

## Google Authentication

Two options for accessing Google APIs (Docs, Drive, Sheets, etc.):

| Method | Use Case | User Interaction |
|--------|----------|------------------|
| **Service Account** | Server-to-server, automation | None |
| **OAuth 2.0** | Access user's personal data | User grants consent |

---

## Google Service Account (Recommended)

For automated/server access. No user interaction required.

### Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → IAM & Admin → Service Accounts
2. Create or select a service account
3. Keys tab → Add Key → Create new key → JSON
4. Save as `service_account_key.json` (add to `.gitignore`)

### Basic Usage

```python
from auth_utils.google import GoogleServiceAccount

auth = GoogleServiceAccount(
    key_path="service_account_key.json",
    scopes=["docs", "drive"]
)

# Build Google API services
docs = auth.build_service("docs", "v1")
drive = auth.build_service("drive", "v3")

# List accessible files
results = drive.files().list(pageSize=10).execute()
```

### Granting Access

The service account has its own identity. To access your files, **share them** with the service account email:

```python
print(auth.email)
# -> your-service-account@project-id.iam.gserviceaccount.com
```

Share a Google Doc or Drive folder with this email address.

### Service Account Info

```python
info = auth.get_info()
# {
#     "type": "service_account",
#     "email": "...",
#     "project_id": "...",
#     "scopes": [...],
# }
```

### Domain-Wide Delegation (Google Workspace)

For Workspace domains with delegation enabled:

```python
# Impersonate a user in your domain
delegated = auth.with_subject("user@yourdomain.com")
drive = delegated.build_service("drive", "v3")
```

---

## Google OAuth 2.0

For accessing a user's personal Google data with their consent.

### Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID (Desktop app)
3. Download JSON as `credentials.json`

Or use the CLI:
```bash
auth-utils google setup
```

### CLI Usage (Recommended)

The CLI handles the entire OAuth flow:

```bash
# Interactive login (opens browser)
auth-utils google login

# Login with specific scopes
auth-utils google login --scopes docs,drive,sheets

# Don't open browser automatically
auth-utils google login --no-browser

# Check token status
auth-utils google status

# Refresh expired token
auth-utils google refresh

# Revoke and clear token
auth-utils google revoke
```

For non-interactive flows (CI/CD, remote servers):

```bash
# Step 1: Generate authorization URL
auth-utils google get-url --scopes docs,drive

# Step 2: User visits URL and authorizes
# Step 3: Complete with redirect URL
auth-utils google complete "http://localhost:8080/?code=..."
```

### Python Usage

```python
from auth_utils.google import GoogleOAuth

auth = GoogleOAuth(scopes=["docs", "drive"])

# First time: user must authorize
if not auth.is_authorized():
    url = auth.get_authorization_url()
    print(f"Visit: {url}")
    redirect_url = input("Paste redirect URL: ")
    auth.fetch_token(redirect_url)

# Build services
docs = auth.build_service("docs", "v1")
drive = auth.build_service("drive", "v3")
```

### Token Management

```python
# Check token status
info = auth.get_token_info()
print(f"Status: {info['status']}")
print(f"Expires in: {info['expires_in']}")

# Revoke access
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

---

## Google Auth - Common

### Available Scopes

Both `GoogleServiceAccount` and `GoogleOAuth` use the same scopes:

| Name | Scope |
|------|-------|
| `docs` | Google Docs read/write |
| `docs_readonly` | Google Docs read only |
| `drive` | Google Drive full access |
| `drive_readonly` | Google Drive read only |
| `drive_file` | Drive files created by app |
| `sheets` | Google Sheets read/write |
| `sheets_readonly` | Google Sheets read only |
| `gmail` | Gmail modify |
| `gmail_readonly` | Gmail read only |
| `calendar` | Google Calendar read/write |
| `calendar_readonly` | Google Calendar read only |

### Error Handling

```python
from auth_utils.google import (
    GoogleServiceAccount,
    GoogleOAuth,
    GoogleAuthError,
    CredentialsNotFoundError,
    TokenError,
    ScopeMismatchError,
)

try:
    auth = GoogleServiceAccount(key_path="key.json")
except CredentialsNotFoundError:
    print("Key file not found")
except GoogleAuthError as e:
    print(f"Auth error: {e}")
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
from auth_utils.google import (
    GoogleServiceAccount,
    GoogleOAuth,
    GoogleAuthError,
)
from auth_utils.zotero import ZoteroClient, ZoteroAuthError

__all__ = [
    "LLMClient",
    "Message",
    "LLMResponse",
    "AuthenticationError",
    "RateLimitError",
    "APIError",
    "GoogleServiceAccount",
    "GoogleOAuth",
    "GoogleAuthError",
    "ZoteroClient",
    "ZoteroAuthError",
]
```

Then import locally:

```python
from your_repo.auth import LLMClient, GoogleServiceAccount, ZoteroClient
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
