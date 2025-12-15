# Integration Guide

## Installation

**For sibling repos (cite-assist, pin-citer, etc.):**

```toml
# pyproject.toml
[project]
dependencies = [
    "auth-utils",
]

[tool.uv.sources]
auth-utils = { path = "../auth-utils", editable = true }
```

```bash
uv sync
```

**For external repos:**

```toml
[project]
dependencies = [
    "auth-utils @ git+https://github.com/donaldbraman/auth-utils.git",
]

[tool.hatch.metadata]
allow-direct-references = true
```

---

## Centralized Credentials

All credentials are stored in the auth-utils repo itself. Sibling repos that import auth-utils automatically get access.

```
auth-utils/
├── .env                          # API keys (auto-loaded on import)
├── google/
│   ├── credentials.json          # OAuth client credentials
│   ├── token.json                # OAuth tokens
│   └── service_account_key.json  # Service account key
```

### Setup

```bash
# Initialize directory structure and see setup instructions
auth-utils init

# Check what's configured
auth-utils status

# Test all configured credentials
auth-utils test
```

### .env format

```bash
# LLM Providers
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=...

# Zotero
ZOTERO_API_KEY=...
ZOTERO_LIBRARY_ID=12345
ZOTERO_LIBRARY_TYPE=user
```

---

## LLM Client

```python
from auth_utils.llm import LLMClient, Message

# Model is REQUIRED - each repo specifies its own
client = LLMClient(provider="gemini", model="gemini-2.5-flash")

response = await client.chat([
    Message(role="system", content="You are a legal assistant."),
    Message(role="user", content="Hello!"),
])

print(response.content)
```

### Parallel Execution

```python
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
        print(f"{provider}: {result.content}")
    else:
        print(f"{provider} error: {result}")
```

### Error Handling

```python
from auth_utils.llm import AuthenticationError, RateLimitError, APIError

try:
    response = await client.chat([Message(role="user", content="Hello")])
except AuthenticationError as e:
    print(f"Invalid API key for {e.provider}")
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after}s")
except APIError as e:
    print(f"API error ({e.status_code}): {e}")
```

---

## Google Service Account

For server/automation access. No user interaction.

### Setup

1. Google Cloud Console -> IAM & Admin -> Service Accounts
2. Create service account -> Keys -> Add Key -> JSON
3. Import the key:
   ```bash
   auth-utils google import-key ~/Downloads/service_account_key.json
   ```
4. **Share your Google Docs/Drive with the service account email**

### Usage

```python
from auth_utils.google import GoogleServiceAccount

auth = GoogleServiceAccount(scopes=["docs", "drive"])  # Uses centralized key

print(auth.email)  # Share files with this email

docs = auth.build_service("docs", "v1")
drive = auth.build_service("drive", "v3")
```

---

## Google OAuth 2.0

For accessing user's personal Google data with consent.

### Setup

1. Google Cloud Console -> APIs & Services -> Credentials
2. Create OAuth 2.0 Client ID (Desktop app)
3. Import credentials:
   ```bash
   auth-utils google import ~/Downloads/credentials.json
   ```

### Usage

```python
from auth_utils.google import GoogleOAuth

auth = GoogleOAuth(scopes=["docs", "drive"])  # Uses centralized credentials

if not auth.is_authorized():
    url = auth.get_authorization_url()
    print(f"Visit: {url}")
    redirect_url = input("Paste redirect URL: ")
    auth.fetch_token(redirect_url)

docs = auth.build_service("docs", "v1")
```

### CLI

```bash
auth-utils google login               # Interactive OAuth
auth-utils google status              # Token status
auth-utils google refresh             # Refresh token
auth-utils google revoke              # Revoke token
auth-utils google import <path>       # Import OAuth credentials
auth-utils google import-key <path>   # Import service account key
```

### Scopes

`docs`, `docs_readonly`, `drive`, `drive_readonly`, `drive_file`, `sheets`, `sheets_readonly`, `gmail`, `gmail_readonly`, `calendar`, `calendar_readonly`

---

## Zotero Client

```python
from auth_utils.zotero import ZoteroClient

client = ZoteroClient()  # Uses ZOTERO_* from .env

items = client.get_items(limit=10)
collections = client.get_collections()
results = client.search_items("machine learning")
```

### Error Handling

```python
from auth_utils.zotero import ZoteroAuthError, ZoteroAPIError

try:
    items = client.get_items()
except ZoteroAuthError:
    print("Authentication failed")
except ZoteroAPIError as e:
    print(f"API error ({e.status_code}): {e}")
```

---

## Direct Gemini Model Access

For use cases requiring direct `genai.GenerativeModel` (binary content, PDF extraction):

```python
# Option 1: Use GoogleProvider to configure, then use genai directly
from auth_utils.llm.providers.google import GoogleProvider

# This configures genai.configure() internally
provider = GoogleProvider(model="gemini-2.5-flash-lite")

# Now genai is configured - use directly
import google.generativeai as genai
model = genai.GenerativeModel("gemini-2.5-flash-lite")
response = model.generate_content([prompt, {"mime_type": "application/pdf", "data": pdf_bytes}])
```

```python
# Option 2: Create a bridge module (like cite-assist does)
# See cite-assist/core/auth_bridge.py for example
```

---

## Updating

```bash
uv lock --refresh-package auth-utils && uv sync
```
