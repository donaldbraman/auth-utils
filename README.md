# auth-utils

Shared authentication infrastructure for LLM providers and Google/Zotero APIs.

## Installation

```bash
uv add git+https://github.com/donaldbraman/auth-utils.git
```

For sibling repos, see [docs/integration-guide.md](docs/integration-guide.md).

## Features

- **LLM Providers**: Unified client for Claude, Gemini, ChatGPT
- **Google OAuth**: OAuth 2.0 for Docs, Drive, Sheets
- **Google Service Account**: For server automation
- **Email/SMTP**: Gmail SMTP with Keychain credential storage
- **Zotero API**: Authentication for citation management

## LLM Client

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export GOOGLE_API_KEY="..."              # Gemini
export OPENAI_API_KEY="sk-..."           # ChatGPT
```

```python
from auth_utils.llm import LLMClient, Message

# Model is REQUIRED
client = LLMClient(provider="gemini", model="gemini-2.5-flash")

response = await client.chat([
    Message(role="user", content="Hello!")
])

print(response.content)
print(f"Tokens: {response.usage.total_tokens}")
```

### Parallel Execution

```python
results = await LLMClient.parallel_chat(
    messages=[Message(role="user", content="Hello!")],
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

## Google OAuth

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

## Google Service Account

```python
from auth_utils.google import GoogleServiceAccount

auth = GoogleServiceAccount(key_path="service_account_key.json", scopes=["docs", "drive"])
print(auth.email)  # Share docs with this email

docs = auth.build_service("docs", "v1")
```

## Email/SMTP

Credentials loaded from: macOS Keychain → environment variables → explicit args.

```bash
# Store password in Keychain (recommended)
auth-utils email store-password gmail

# Or use environment variables
export GMAIL_SMTP_USER="user@gmail.com"
export GMAIL_SMTP_PASSWORD="xxxx-xxxx-xxxx-xxxx"  # App password
```

```python
from auth_utils.email import SMTPClient

client = SMTPClient(provider="gmail")
client.send(
    to=["recipient@example.com"],
    subject="Hello",
    body="<p>HTML message</p>",
    html=True,
)
```

## Zotero

```bash
export ZOTERO_API_KEY="..."
export ZOTERO_LIBRARY_ID="12345"
export ZOTERO_LIBRARY_TYPE="user"  # or "group"
```

```python
from auth_utils.zotero import ZoteroClient

client = ZoteroClient()
items = client.get_items(limit=10)
results = client.search_items("machine learning")
```

## Development

```bash
git clone https://github.com/donaldbraman/auth-utils.git
cd auth-utils
uv sync --all-extras
uv run pytest
uv run ruff check --fix && uv run ruff format
```

## License

MIT
