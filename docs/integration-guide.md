# Integration Guide

Add auth-utils to your `pyproject.toml`:

```toml
[project]
dependencies = [
    "auth-utils @ git+https://github.com/donaldbraman/auth-utils.git",
]

[tool.hatch.metadata]
allow-direct-references = true
```

```bash
uv sync
```

---

## LLM Client

```python
from auth_utils.llm import LLMClient, Message, LLMResponse

# Model is required - each repo specifies its own
client = LLMClient(provider="claude", model="claude-sonnet-4-20250514")

response = await client.chat([
    Message(role="system", content="You are a legal writing assistant."),
    Message(role="user", content="Hello!"),
])

print(response.content)
print(f"Tokens: {response.usage.total_tokens}")
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

### Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export GOOGLE_API_KEY="..."              # Gemini
export OPENAI_API_KEY="sk-..."           # ChatGPT
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

For automated/server access. No user interaction.

### Setup

1. Google Cloud Console → IAM & Admin → Service Accounts
2. Create service account → Keys → Add Key → JSON
3. Save as `service_account_key.json` (gitignore it)
4. **Share your Google Docs/Drive with the service account email**

### Usage

```python
from auth_utils.google import GoogleServiceAccount

auth = GoogleServiceAccount(key_path="service_account_key.json", scopes=["docs", "drive"])

# Get the email to share files with
print(auth.email)  # -> your-sa@project.iam.gserviceaccount.com

# Build API services
docs = auth.build_service("docs", "v1")
drive = auth.build_service("drive", "v3")
```

---

## Google OAuth 2.0

For accessing a user's personal Google data with their consent.

### Setup

1. Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID (Desktop app)
3. Download JSON as `credentials.json`

### Usage

```python
from auth_utils.google import GoogleOAuth

auth = GoogleOAuth(scopes=["docs", "drive"])

if not auth.is_authorized():
    url = auth.get_authorization_url()
    print(f"Visit: {url}")
    redirect_url = input("Paste redirect URL: ")
    auth.fetch_token(redirect_url)

docs = auth.build_service("docs", "v1")
```

### CLI

```bash
auth-utils google login     # Interactive OAuth
auth-utils google status    # Token status
auth-utils google refresh   # Refresh token
auth-utils google revoke    # Revoke token
```

### Scopes

`docs`, `docs_readonly`, `drive`, `drive_readonly`, `drive_file`, `sheets`, `sheets_readonly`, `gmail`, `gmail_readonly`, `calendar`, `calendar_readonly`

---

## Zotero Client

```python
from auth_utils.zotero import ZoteroClient

client = ZoteroClient()  # Uses env vars

items = client.get_items(limit=10)
collections = client.get_collections()
results = client.search_items("machine learning")
```

### Environment Variables

```bash
export ZOTERO_API_KEY="..."
export ZOTERO_LIBRARY_ID="12345"
export ZOTERO_LIBRARY_TYPE="user"  # or "group"
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

## Updating

```bash
uv lock --refresh-package auth-utils && uv sync
```
