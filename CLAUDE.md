# Claude Code Instructions for auth-utils

Shared LLM authentication infrastructure for multi-provider support (Claude, Gemini, ChatGPT).

**Global guides:** See cross-repo/.claude/guides/

---

## Critical Rules

- NEVER create files outside defined directories
- NEVER use mocks - integration tests with real data only
- NEVER use bare `python` - always `uv run python`
- ALWAYS use `uv run pytest` for tests
- ALWAYS run `uv run ruff check --fix && uv run ruff format` before commits

---

## Stack

| Tool | Purpose |
|------|---------|
| uv | Package management |
| ruff | Linting & formatting |
| pytest | Integration testing |
| pre-commit | Commit hooks |

---

## Key Files

| Path | Purpose |
|------|---------|
| `src/auth_utils/llm/client.py` | Unified LLMClient with parallel_chat() |
| `src/auth_utils/llm/providers/` | Anthropic, OpenAI, Google implementations |
| `src/auth_utils/llm/exceptions.py` | Unified exception hierarchy |
| `src/auth_utils/llm/models.py` | Message, LLMResponse, UsageStats |

---

## Environment Variables

| Variable | Provider |
|----------|----------|
| `ANTHROPIC_API_KEY` | Claude |
| `OPENAI_API_KEY` | ChatGPT |
| `GOOGLE_API_KEY` | Gemini |

---

## Usage by Other Repos

Sibling repos (write-assist, cite-assist, etc.) depend on this package:

```toml
# In pyproject.toml
dependencies = [
    "auth-utils @ git+https://github.com/donaldbraman/auth-utils.git",
]

[tool.hatch.metadata]
allow-direct-references = true
```

Then import:
```python
from auth_utils.llm import LLMClient, Message, LLMResponse
```

---

## Development Workflow

```bash
# Install deps
uv sync --all-extras

# Run tests (skips integration tests without API keys)
uv run pytest -v

# Lint & format
uv run ruff check --fix && uv run ruff format
```

---

## Adding New Providers

1. Create `src/auth_utils/llm/providers/{provider}.py`
2. Implement `BaseLLMProvider` abstract class
3. Register in `PROVIDERS` dict in `client.py`
4. Add tests in `tests/test_llm_integration.py`
5. Update README.md with new provider info
