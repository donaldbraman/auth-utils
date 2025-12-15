# Claude Code Instructions for auth-utils

Shared authentication infrastructure for LLM providers (Claude, Gemini, ChatGPT), Google APIs, and Zotero.

---

## Critical Rules

- NEVER use mocks - integration tests with real APIs only
- NEVER use bare `python` - always `uv run python`
- ALWAYS run `uv run ruff check --fix && uv run ruff format` before commits

---

## Stack

| Tool | Purpose |
|------|---------|
| uv | Package management |
| ruff | Linting & formatting |
| pytest | Integration testing |

---

## Key Files

| Path | Purpose |
|------|---------|
| `src/auth_utils/llm/client.py` | LLMClient with parallel_chat() |
| `src/auth_utils/llm/providers/` | Anthropic, OpenAI, Google implementations |
| `src/auth_utils/llm/exceptions.py` | AuthenticationError, RateLimitError, APIError |
| `src/auth_utils/llm/models.py` | Message, LLMResponse, UsageStats |
| `src/auth_utils/google/oauth.py` | GoogleOAuth for user consent flows |
| `src/auth_utils/google/service_account.py` | GoogleServiceAccount for automation |
| `src/auth_utils/zotero/client.py` | ZoteroClient with local+cloud support |

---

## Environment Variables

| Variable | Provider |
|----------|----------|
| `ANTHROPIC_API_KEY` | Claude |
| `OPENAI_API_KEY` | ChatGPT |
| `GOOGLE_API_KEY` | Gemini |
| `ZOTERO_API_KEY` | Zotero cloud |
| `ZOTERO_LIBRARY_ID` | Zotero library |

---

## Usage by Sibling Repos

**cite-assist, pin-citer, write-assist** use local editable source:

```toml
# pyproject.toml
[project]
dependencies = ["auth-utils"]

[tool.uv.sources]
auth-utils = { path = "../auth-utils", editable = true }
```

**External repos** use git URL:

```toml
dependencies = ["auth-utils @ git+https://github.com/donaldbraman/auth-utils.git"]

[tool.hatch.metadata]
allow-direct-references = true
```

---

## Quick Reference

```python
# LLM Client (model is REQUIRED)
from auth_utils.llm import LLMClient, Message
client = LLMClient(provider="gemini", model="gemini-2.5-flash")
response = await client.chat([Message(role="user", content="Hello")])

# Google OAuth
from auth_utils.google import GoogleOAuth
auth = GoogleOAuth(scopes=["docs", "drive"])

# Zotero
from auth_utils.zotero import ZoteroClient
client = ZoteroClient()  # uses env vars
```

---

## Development

```bash
uv sync --all-extras           # Install deps
uv run pytest -v               # Run tests
uv run ruff check --fix && uv run ruff format  # Lint
```

---

## Adding New Providers

1. Create `src/auth_utils/llm/providers/{provider}.py`
2. Implement `BaseLLMProvider` abstract class
3. Register in `PROVIDERS` dict in `client.py`
4. Add tests in `tests/`
5. Update docs/integration-guide.md
