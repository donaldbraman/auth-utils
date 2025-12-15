"""Centralized credential configuration.

All credentials are stored in the auth-utils repo root:
    .env                          - API keys (ANTHROPIC_API_KEY, etc.)
    google/credentials.json       - Google OAuth client credentials
    google/token.json             - Google OAuth tokens
    google/service_account_key.json - Google service account key

This module auto-loads the .env file on import, making credentials
available to all auth-utils modules and any code that imports them.

Sibling repos that depend on auth-utils automatically get access to
these credentials without any additional configuration.
"""

import os
from pathlib import Path

# Repository root (where this package is installed from)
# __file__ is src/auth_utils/config.py, so 3 levels up
REPO_ROOT = Path(__file__).parent.parent.parent
GOOGLE_DIR = REPO_ROOT / "google"

# Credential file paths
ENV_FILE = REPO_ROOT / ".env"
GOOGLE_CREDENTIALS = GOOGLE_DIR / "credentials.json"
GOOGLE_TOKEN = GOOGLE_DIR / "token.json"
GOOGLE_SERVICE_ACCOUNT = GOOGLE_DIR / "service_account_key.json"


def _load_env_file(env_path: Path) -> dict[str, str]:
    """Load environment variables from a file.

    Args:
        env_path: Path to .env file.

    Returns:
        Dictionary of loaded variables.
    """
    loaded = {}
    if not env_path.exists():
        return loaded

    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            # Remove surrounding quotes
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            # Only set if not already in environment (env vars take precedence)
            if key and key not in os.environ:
                os.environ[key] = value
                loaded[key] = value

    return loaded


def ensure_google_dir() -> Path:
    """Create google credentials directory if it doesn't exist.

    Returns:
        Path to google directory.
    """
    GOOGLE_DIR.mkdir(parents=True, exist_ok=True)
    return GOOGLE_DIR


def get_credential_status() -> dict:
    """Get status of all configured credentials.

    Returns:
        Dictionary with credential status.
    """
    return {
        "repo_root": str(REPO_ROOT),
        "env_file": ENV_FILE.exists(),
        "llm": {
            "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "google": bool(os.environ.get("GOOGLE_API_KEY")),
            "openai": bool(os.environ.get("OPENAI_API_KEY")),
        },
        "google": {
            "credentials": GOOGLE_CREDENTIALS.exists(),
            "token": GOOGLE_TOKEN.exists(),
            "service_account": GOOGLE_SERVICE_ACCOUNT.exists(),
        },
        "zotero": {
            "api_key": bool(os.environ.get("ZOTERO_API_KEY")),
            "library_id": bool(os.environ.get("ZOTERO_LIBRARY_ID")),
        },
    }


# Auto-load .env from repo root on import
_loaded = _load_env_file(ENV_FILE)
