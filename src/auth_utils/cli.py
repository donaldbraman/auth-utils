"""CLI for auth-utils - credential management.

Usage:
    auth-utils init              # Create directories, show setup instructions
    auth-utils status            # Show all credential status
    auth-utils google login      # Interactive OAuth login
    auth-utils google status     # Show OAuth token status
    auth-utils google refresh    # Refresh OAuth token
    auth-utils google revoke     # Revoke OAuth token
"""

from __future__ import annotations

import argparse
import sys
import webbrowser


def cmd_init() -> int:
    """Initialize auth-utils credential directory structure."""
    from auth_utils.config import (
        ENV_FILE,
        GOOGLE_CREDENTIALS,
        GOOGLE_DIR,
        GOOGLE_SERVICE_ACCOUNT,
        GOOGLE_TOKEN,
        REPO_ROOT,
        ensure_google_dir,
    )

    print("=" * 60)
    print("AUTH-UTILS SETUP")
    print("=" * 60)
    print()
    print(f"Repository: {REPO_ROOT}")
    print()

    # Create directories
    ensure_google_dir()
    print(f"Created: {GOOGLE_DIR}/")
    print()

    # Show what goes where
    print("Credential locations:")
    print()
    print(f"  {ENV_FILE}")
    print("    API keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY")
    print("    Zotero:   ZOTERO_API_KEY, ZOTERO_LIBRARY_ID, ZOTERO_LIBRARY_TYPE")
    print()
    print(f"  {GOOGLE_CREDENTIALS}")
    print("    OAuth client credentials from Google Cloud Console")
    print()
    print(f"  {GOOGLE_TOKEN}")
    print("    OAuth tokens (created by 'auth-utils google login')")
    print()
    print(f"  {GOOGLE_SERVICE_ACCOUNT}")
    print("    Service account key from Google Cloud Console")
    print()
    print("-" * 60)
    print()

    # Check what's already configured
    status = _check_status()

    if status["env_file"]:
        print(".env exists")
    else:
        print("Create .env with your API keys:")
        print()
        print(f"  cat > {ENV_FILE} << 'EOF'")
        print("  ANTHROPIC_API_KEY=sk-ant-...")
        print("  OPENAI_API_KEY=sk-...")
        print("  GOOGLE_API_KEY=...")
        print("  ZOTERO_API_KEY=...")
        print("  ZOTERO_LIBRARY_ID=12345")
        print("  ZOTERO_LIBRARY_TYPE=user")
        print("  EOF")
        print()

    if status["google"]["credentials"]:
        print("Google credentials.json exists")
    else:
        print("For Google OAuth, download credentials from:")
        print("  https://console.cloud.google.com/apis/credentials")
        print(f"  Save as: {GOOGLE_CREDENTIALS}")
        print()

    return 0


def cmd_status() -> int:
    """Show status of all configured credentials."""
    from auth_utils.config import REPO_ROOT

    status = _check_status()

    print("=" * 60)
    print("AUTH-UTILS CREDENTIAL STATUS")
    print("=" * 60)
    print()
    print(f"Repository: {REPO_ROOT}")
    print()

    # LLM Providers
    print("LLM Providers:")
    for provider, configured in status["llm"].items():
        mark = "[x]" if configured else "[ ]"
        print(f"  {mark} {provider}")
    print()

    # Google
    print("Google:")
    print(f"  credentials.json:       {'[x]' if status['google']['credentials'] else '[ ]'}")
    print(f"  token.json:             {'[x]' if status['google']['token'] else '[ ]'}")
    print(f"  service_account_key:    {'[x]' if status['google']['service_account'] else '[ ]'}")
    print()

    # Zotero
    print("Zotero:")
    print(f"  API key:    {'[x]' if status['zotero']['api_key'] else '[ ]'}")
    print(f"  Library ID: {'[x]' if status['zotero']['library_id'] else '[ ]'}")
    print()

    return 0


def _check_status() -> dict:
    """Get credential status."""
    from auth_utils.config import get_credential_status

    return get_credential_status()


def google_login(scopes: list[str], no_browser: bool = False) -> int:
    """Interactive Google OAuth login."""
    from auth_utils.google import CredentialsNotFoundError, GoogleOAuth

    print("=" * 60)
    print("AUTH-UTILS GOOGLE LOGIN")
    print("=" * 60)

    try:
        auth = GoogleOAuth(scopes=scopes)
    except CredentialsNotFoundError as e:
        print(f"\nError: {e}")
        print("Run 'auth-utils init' for setup instructions")
        return 1

    # Check if already authorized AND token is valid
    info = auth.get_token_info()
    if auth.is_authorized() and info["status"] == "valid":
        print("\nAlready authorized with valid token")
        return google_status(scopes)

    if info["status"] == "expired":
        print("\nToken expired, attempting refresh...")
        try:
            auth.get_credentials()  # Triggers refresh
            new_info = auth.get_token_info()
            if new_info["status"] == "valid":
                print("Token refreshed successfully!")
                return google_status(scopes)
        except Exception as e:
            print(f"Refresh failed: {e}")
            print("Starting new authorization flow...")

    print(f"\nScopes: {', '.join(scopes)}")
    print("\nA browser window will open for Google consent.")
    print("After granting access, copy the redirect URL back here.\n")

    url = auth.get_authorization_url()
    print(f"Authorization URL:\n{url}\n")

    if not no_browser:
        webbrowser.open(url)

    redirect_url = input("Paste redirect URL: ").strip()
    if not redirect_url:
        print("No URL provided; aborting.")
        return 1

    try:
        auth.fetch_token(redirect_url)
        print("\nToken saved successfully!")
        return google_status(scopes)
    except Exception as e:
        print(f"\nError: {e}")
        return 1


def google_status(scopes: list[str]) -> int:
    """Show Google OAuth token status."""
    from auth_utils.google import CredentialsNotFoundError, GoogleOAuth

    try:
        auth = GoogleOAuth(scopes=scopes)
    except CredentialsNotFoundError as e:
        print(f"Error: {e}")
        print("Run 'auth-utils init' for setup instructions")
        return 1

    info = auth.get_token_info()

    if info["status"] == "no_token":
        print("No token found - run 'auth-utils google login'")
        return 1

    print(f"Status     : {info['status']}")
    print(f"Scopes     : {', '.join(info.get('scopes', []))}")
    print(f"Expires in : {info.get('expires_in', 'unknown')}")
    print(f"Refreshed  : {info.get('last_refresh', 'never')}")
    return 0


def google_refresh(scopes: list[str]) -> int:
    """Refresh Google OAuth token."""
    from auth_utils.google import CredentialsNotFoundError, GoogleOAuth, TokenError

    print("=" * 60)
    print("REFRESHING OAUTH TOKEN")
    print("=" * 60)

    try:
        auth = GoogleOAuth(scopes=scopes)
    except CredentialsNotFoundError as e:
        print(f"Error: {e}")
        print("Run 'auth-utils init' for setup instructions")
        return 1

    if not auth.is_authorized():
        print("No valid token - run 'auth-utils google login'")
        return 1

    try:
        auth.get_credentials()  # Triggers refresh if expired
        print("\nToken refreshed successfully!")
        return google_status(scopes)
    except TokenError as e:
        print(f"\nRefresh failed: {e}")
        print("You may need to re-authenticate: auth-utils google login")
        return 1


def google_revoke(scopes: list[str]) -> int:
    """Revoke Google OAuth token."""
    from auth_utils.google import CredentialsNotFoundError, GoogleOAuth

    try:
        auth = GoogleOAuth(scopes=scopes)
    except CredentialsNotFoundError:
        print("No credentials to revoke")
        return 0

    auth.revoke_token()
    print("Token revoked and local cache cleared")
    return 0


def parse_scopes(scope_str: str | None) -> list[str]:
    """Parse comma-separated scopes."""
    if not scope_str:
        return ["docs", "drive"]  # Default scopes
    return [s.strip() for s in scope_str.split(",")]


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="auth-utils",
        description="Centralized credential management for LLM and Google APIs",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # init command
    subparsers.add_parser("init", help="Initialize credential directories")

    # status command
    subparsers.add_parser("status", help="Show all credential status")

    # Google subcommand
    google_parser = subparsers.add_parser("google", help="Google OAuth management")
    google_subparsers = google_parser.add_subparsers(dest="google_command", help="Command")

    # google login
    login_parser = google_subparsers.add_parser("login", help="Interactive OAuth login")
    login_parser.add_argument(
        "--scopes",
        type=str,
        default="docs,drive",
        help="Comma-separated scopes (default: docs,drive)",
    )
    login_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't open browser automatically",
    )

    # google status
    status_parser = google_subparsers.add_parser("status", help="Show token status")
    status_parser.add_argument(
        "--scopes",
        type=str,
        default="docs,drive",
        help="Comma-separated scopes (default: docs,drive)",
    )

    # google refresh
    refresh_parser = google_subparsers.add_parser("refresh", help="Refresh token")
    refresh_parser.add_argument(
        "--scopes",
        type=str,
        default="docs,drive",
        help="Comma-separated scopes (default: docs,drive)",
    )

    # google revoke
    revoke_parser = google_subparsers.add_parser("revoke", help="Revoke token")
    revoke_parser.add_argument(
        "--scopes",
        type=str,
        default="docs,drive",
        help="Comma-separated scopes (default: docs,drive)",
    )

    args = parser.parse_args(argv or sys.argv[1:])

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "init":
        return cmd_init()

    if args.command == "status":
        return cmd_status()

    if args.command == "google":
        scopes = parse_scopes(getattr(args, "scopes", None))

        if args.google_command == "login":
            return google_login(scopes, args.no_browser)
        elif args.google_command == "status":
            return google_status(scopes)
        elif args.google_command == "refresh":
            return google_refresh(scopes)
        elif args.google_command == "revoke":
            return google_revoke(scopes)
        else:
            google_parser.print_help()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
