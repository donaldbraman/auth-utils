"""CLI for auth-utils - credential management.

Usage:
    auth-utils init                        # Create directories, show setup instructions
    auth-utils status                      # Show all credential status
    auth-utils test                        # Test all configured credentials
    auth-utils google login                # Interactive OAuth login
    auth-utils google status               # Show OAuth token status
    auth-utils google refresh              # Refresh OAuth token
    auth-utils google revoke               # Revoke OAuth token
    auth-utils google import <path>        # Import OAuth credentials
    auth-utils google import-key <path>    # Import service account key
    auth-utils email status                # Show email/SMTP credential status
    auth-utils email test <provider>       # Test SMTP connection
    auth-utils email store-password <provider>  # Store password in Keychain
    auth-utils email imap-test             # Test IMAP connection
    auth-utils email search                # Search emails via IMAP
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import shutil
import sys
import webbrowser
from pathlib import Path


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

    # Email/SMTP
    print("Email/SMTP:")
    email_status = status.get("email", {})
    gmail = email_status.get("gmail", {})
    if gmail.get("keychain"):
        print(f"  [x] Gmail Keychain: {gmail.get('keychain_user', 'configured')}")
    else:
        print("  [ ] Gmail Keychain: not configured")
    if gmail.get("env"):
        print(f"  [x] Gmail Environment: {gmail.get('env_user', 'configured')}")
    else:
        print("  [ ] Gmail Environment: not configured")
    print()

    return 0


def cmd_test() -> int:
    """Test all configured credentials."""
    # Ensure .env is loaded from config
    import auth_utils.config  # noqa: F401

    print("=" * 60)
    print("AUTH-UTILS CREDENTIAL TEST")
    print("=" * 60)
    print()

    all_passed = True

    # Test LLM Providers
    print("LLM Providers:")
    all_passed &= _test_llm_providers()
    print()

    # Test Google Service Account
    print("Google Service Account:")
    all_passed &= _test_google_service_account()
    print()

    # Test Zotero
    print("Zotero:")
    all_passed &= _test_zotero()
    print()

    # Test Email/SMTP
    print("Email/SMTP:")
    all_passed &= _test_email()
    print()

    if all_passed:
        print("All configured credentials working!")
    else:
        print("Some credentials failed - check output above")

    return 0 if all_passed else 1


def _test_llm_providers() -> bool:
    """Test LLM provider connections."""
    import os

    all_passed = True
    test_models = {
        "claude": ("claude-haiku-4-5-20251001", "ANTHROPIC_API_KEY"),
        "gemini": ("gemini-2.5-flash-lite", "GOOGLE_API_KEY"),
        "chatgpt": ("gpt-4o-mini", "OPENAI_API_KEY"),
    }

    for provider, (model, env_var) in test_models.items():
        if not os.environ.get(env_var):
            print(f"  [ ] {provider} - not configured")
            continue

        try:
            from auth_utils.llm import LLMClient, Message

            client = LLMClient(provider=provider, model=model)
            response = asyncio.run(
                client.chat([Message(role="user", content="Say 'ok' and nothing else")])
            )
            if response.content:
                print(f"  [✓] {provider} - {model}")
            else:
                print(f"  [✗] {provider} - empty response")
                all_passed = False
        except Exception as e:
            print(f"  [✗] {provider} - {e}")
            all_passed = False

    return all_passed


def _test_google_service_account() -> bool:
    """Test Google service account."""
    from auth_utils.config import GOOGLE_SERVICE_ACCOUNT

    if not GOOGLE_SERVICE_ACCOUNT.exists():
        print("  [ ] not configured")
        return True  # Not a failure if not configured

    try:
        from auth_utils.google import GoogleServiceAccount

        auth = GoogleServiceAccount(scopes=["drive_readonly"])
        email = auth.email
        print(f"  [✓] {email}")
        return True
    except Exception as e:
        print(f"  [✗] {e}")
        return False


def _test_zotero() -> bool:
    """Test Zotero API connection."""
    import os

    if not os.environ.get("ZOTERO_API_KEY") or not os.environ.get("ZOTERO_LIBRARY_ID"):
        print("  [ ] not configured")
        return True  # Not a failure if not configured

    try:
        from auth_utils.zotero import ZoteroClient

        client = ZoteroClient()
        items = client.get_items(limit=100)
        count = len(items)
        print(f"  [✓] connected - {count}+ items")
        return True
    except Exception as e:
        print(f"  [✗] {e}")
        return False


def _test_email() -> bool:
    """Test email/SMTP connections."""
    from auth_utils.config import get_credential_status

    status = get_credential_status()
    email_status = status.get("email", {})
    gmail = email_status.get("gmail", {})

    if not gmail.get("keychain") and not gmail.get("env"):
        print("  [ ] gmail - not configured")
        return True  # Not a failure if not configured

    try:
        from auth_utils.email import SMTPClient

        client = SMTPClient(provider="gmail")
        client.test_connection()
        user = client.user
        print(f"  [✓] gmail - {user}")
        return True
    except Exception as e:
        print(f"  [✗] gmail - {e}")
        return False


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


def google_import(source_path: str) -> int:
    """Import OAuth credentials from a file."""
    from auth_utils.config import GOOGLE_CREDENTIALS, ensure_google_dir

    source = Path(source_path).expanduser()

    if not source.exists():
        print(f"Error: File not found: {source}")
        return 1

    # Validate JSON format
    try:
        with open(source) as f:
            data = json.load(f)

        if "installed" not in data and "web" not in data:
            print("Error: Invalid OAuth credentials format")
            print("Expected 'installed' or 'web' key in JSON")
            return 1

        # Get client ID for confirmation
        key = "installed" if "installed" in data else "web"
        client_id = data[key].get("client_id", "unknown")

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        return 1

    # Create directory and copy
    ensure_google_dir()
    shutil.copy2(source, GOOGLE_CREDENTIALS)

    print("Imported OAuth credentials")
    print(f"  From: {source}")
    print(f"  To:   {GOOGLE_CREDENTIALS}")
    print(f"  Client ID: {client_id[:40]}...")
    print()
    print("Next: Run 'auth-utils google login' to authorize")
    return 0


def google_import_key(source_path: str) -> int:
    """Import service account key from a file."""
    from auth_utils.config import GOOGLE_SERVICE_ACCOUNT, ensure_google_dir

    source = Path(source_path).expanduser()

    if not source.exists():
        print(f"Error: File not found: {source}")
        return 1

    # Validate JSON format
    try:
        with open(source) as f:
            data = json.load(f)

        if data.get("type") != "service_account":
            print("Error: Invalid service account key format")
            print(f"Expected type 'service_account', got '{data.get('type')}'")
            return 1

        email = data.get("client_email", "unknown")
        project = data.get("project_id", "unknown")

    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}")
        return 1

    # Create directory and copy
    ensure_google_dir()
    shutil.copy2(source, GOOGLE_SERVICE_ACCOUNT)

    print("Imported service account key")
    print(f"  From: {source}")
    print(f"  To:   {GOOGLE_SERVICE_ACCOUNT}")
    print(f"  Email: {email}")
    print(f"  Project: {project}")
    print()
    print("Remember to share your Google resources with the service account email!")
    return 0


def parse_scopes(scope_str: str | None) -> list[str]:
    """Parse comma-separated scopes."""
    if not scope_str:
        return ["docs", "drive"]  # Default scopes
    return [s.strip() for s in scope_str.split(",")]


# =============================================================================
# Email Commands
# =============================================================================


def email_status() -> int:
    """Show email/SMTP credential status."""
    import os

    from auth_utils.email.providers.gmail import get_gmail_keychain_status

    print("=" * 60)
    print("EMAIL/SMTP CREDENTIAL STATUS")
    print("=" * 60)
    print()

    # Gmail
    print("Gmail (smtp.gmail.com):")
    kc_status = get_gmail_keychain_status()
    if kc_status["configured"]:
        print(f"  [x] Keychain: {kc_status['user']}")
    else:
        print("  [ ] Keychain: not configured")

    env_user = os.environ.get("GMAIL_SMTP_USER")
    env_pass = os.environ.get("GMAIL_SMTP_PASSWORD")
    if env_user and env_pass:
        print(f"  [x] Environment: {env_user}")
    elif env_user:
        print(f"  [ ] Environment: {env_user} (no password)")
    else:
        print("  [ ] Environment: not configured")

    print()
    return 0


def email_test(provider: str, recipient: str | None = None) -> int:
    """Test SMTP connection."""
    from auth_utils.email import SMTPAuthError, SMTPClient, SMTPConnectionError

    print("=" * 60)
    print(f"TESTING {provider.upper()} SMTP")
    print("=" * 60)
    print()

    try:
        client = SMTPClient(provider=provider)
        user = client.user
        print(f"User: {user}")
        print(f"Server: {client._provider.host}:{client._provider.port}")
        print()

        print("Testing connection...", end=" ", flush=True)
        client.test_connection()
        print("[OK]")

        if recipient:
            print(f"Sending test email to {recipient}...", end=" ", flush=True)
            client.send(
                to=[recipient],
                subject="auth-utils: Test Email",
                body="<p>This is a test email from <code>auth-utils email test</code>.</p>"
                "<p>If you received this, your SMTP configuration is working.</p>",
                html=True,
            )
            print("[OK]")

        print()
        print("SMTP configuration is working!")
        return 0

    except SMTPAuthError as e:
        print("[FAILED]")
        print(f"\nAuthentication error: {e}")
        print("\nTips:")
        print("  - Ensure 2-Step Verification is enabled on your Google account")
        print("  - Generate an App Password at: https://myaccount.google.com/apppasswords")
        print("  - Use the 16-character app password, not your regular password")
        return 1

    except SMTPConnectionError as e:
        print("[FAILED]")
        print(f"\nConnection error: {e}")
        return 1

    except Exception as e:
        print("[FAILED]")
        print(f"\nError: {e}")
        return 1


def email_store_password(provider: str) -> int:
    """Store SMTP password in macOS Keychain."""
    if sys.platform != "darwin":
        print("Error: Keychain storage is only available on macOS")
        return 1

    if provider != "gmail":
        print(f"Error: Unknown provider '{provider}'. Supported: gmail")
        return 1

    from auth_utils.email.providers.gmail import store_gmail_password

    print("=" * 60)
    print("STORE GMAIL PASSWORD IN KEYCHAIN")
    print("=" * 60)
    print()
    print("This will store your Gmail app password in macOS Keychain.")
    print()
    print("To get an app password:")
    print("  1. Enable 2-Step Verification: https://myaccount.google.com/security")
    print("  2. Create App Password: https://myaccount.google.com/apppasswords")
    print()

    user = input("Gmail address: ").strip()
    if not user:
        print("No email provided; aborting.")
        return 1

    password = getpass.getpass("App password: ")
    if not password:
        print("No password provided; aborting.")
        return 1

    if store_gmail_password(user, password):
        print()
        print(f"Password stored in Keychain as 'auth-utils-gmail' for {user}")
        print("Test with: auth-utils email test gmail")
        return 0
    else:
        print()
        print("Failed to store password in Keychain")
        return 1


def email_imap_test(provider: str) -> int:
    """Test IMAP connection."""
    from auth_utils.email import IMAPClient, SMTPAuthError, SMTPConnectionError

    print("=" * 60)
    print(f"TESTING {provider.upper()} IMAP")
    print("=" * 60)
    print()

    try:
        with IMAPClient(provider=provider) as client:
            user = client.user
            print(f"User: {user}")
            print(f"Server: {client._host}:{client._port}")
            print()

            print("Testing connection...", end=" ", flush=True)
            client.test_connection()
            print("[OK]")

            print("Listing folders...", end=" ", flush=True)
            folders = client.list_folders()
            print(f"[OK] {len(folders)} folders")

            print()
            print("IMAP configuration is working!")
            return 0

    except SMTPAuthError as e:
        print("[FAILED]")
        print(f"\nAuthentication error: {e}")
        print("\nTips:")
        print("  - Ensure IMAP is enabled in Gmail settings")
        print("  - Use the same app password as SMTP")
        return 1

    except SMTPConnectionError as e:
        print("[FAILED]")
        print(f"\nConnection error: {e}")
        return 1

    except Exception as e:
        print("[FAILED]")
        print(f"\nError: {e}")
        return 1


def email_search(
    provider: str,
    folder: str,
    from_: str | None,
    subject: str | None,
    since: str | None,
    limit: int,
) -> int:
    """Search emails via IMAP."""
    from datetime import datetime

    from auth_utils.email import IMAPClient, SMTPAuthError, SMTPConnectionError

    print("=" * 60)
    print("SEARCHING EMAILS VIA IMAP")
    print("=" * 60)
    print()

    # Parse since date if provided
    since_date = None
    if since:
        try:
            since_date = datetime.strptime(since, "%Y-%m-%d").date()
        except ValueError:
            print(f"Error: Invalid date format '{since}'. Use YYYY-MM-DD.")
            return 1

    try:
        with IMAPClient(provider=provider) as client:
            print(f"User: {client.user}")
            print(f"Folder: {folder}")
            print()

            messages = client.search(
                folder=folder,
                from_=from_,
                subject=subject,
                since=since_date,
                limit=limit,
            )

            if not messages:
                print("No messages found.")
                return 0

            print(f"Found {len(messages)} message(s):\n")
            for msg in messages:
                date_str = msg.date.strftime("%Y-%m-%d %H:%M") if msg.date else "unknown"
                print(f"  [{date_str}] {msg.sender}")
                print(f"    Subject: {msg.subject}")
                print(f"    Preview: {msg.snippet}")
                print()

            return 0

    except SMTPAuthError as e:
        print(f"Authentication error: {e}")
        return 1

    except SMTPConnectionError as e:
        print(f"Connection error: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


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

    # test command
    subparsers.add_parser("test", help="Test all configured credentials")

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

    # google import
    import_parser = google_subparsers.add_parser("import", help="Import OAuth credentials")
    import_parser.add_argument("path", help="Path to credentials.json file")

    # google import-key
    import_key_parser = google_subparsers.add_parser(
        "import-key", help="Import service account key"
    )
    import_key_parser.add_argument("path", help="Path to service account JSON key file")

    # Email subcommand
    email_parser = subparsers.add_parser("email", help="Email/SMTP management")
    email_subparsers = email_parser.add_subparsers(dest="email_command", help="Command")

    # email status
    email_subparsers.add_parser("status", help="Show SMTP credential status")

    # email test
    email_test_parser = email_subparsers.add_parser("test", help="Test SMTP connection")
    email_test_parser.add_argument(
        "provider",
        nargs="?",
        default="gmail",
        help="Provider name (default: gmail)",
    )
    email_test_parser.add_argument(
        "--to",
        type=str,
        help="Send test email to this address",
    )

    # email store-password
    email_store_parser = email_subparsers.add_parser(
        "store-password", help="Store password in Keychain"
    )
    email_store_parser.add_argument(
        "provider",
        nargs="?",
        default="gmail",
        help="Provider name (default: gmail)",
    )

    # email imap-test
    email_imap_test_parser = email_subparsers.add_parser("imap-test", help="Test IMAP connection")
    email_imap_test_parser.add_argument(
        "provider",
        nargs="?",
        default="gmail",
        help="Provider name (default: gmail)",
    )

    # email search
    email_search_parser = email_subparsers.add_parser("search", help="Search emails via IMAP")
    email_search_parser.add_argument(
        "--provider",
        type=str,
        default="gmail",
        help="Provider name (default: gmail)",
    )
    email_search_parser.add_argument(
        "--folder",
        type=str,
        default="INBOX",
        help="Mail folder (default: INBOX)",
    )
    email_search_parser.add_argument(
        "--from",
        dest="from_",
        type=str,
        help="Filter by sender",
    )
    email_search_parser.add_argument(
        "--subject",
        type=str,
        help="Filter by subject",
    )
    email_search_parser.add_argument(
        "--since",
        type=str,
        help="Messages since date (YYYY-MM-DD)",
    )
    email_search_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max messages to return (default: 10)",
    )

    args = parser.parse_args(argv or sys.argv[1:])

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "init":
        return cmd_init()

    if args.command == "status":
        return cmd_status()

    if args.command == "test":
        return cmd_test()

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
        elif args.google_command == "import":
            return google_import(args.path)
        elif args.google_command == "import-key":
            return google_import_key(args.path)
        else:
            google_parser.print_help()
            return 0

    if args.command == "email":
        if args.email_command == "status":
            return email_status()
        elif args.email_command == "test":
            return email_test(args.provider, args.to)
        elif args.email_command == "store-password":
            return email_store_password(args.provider)
        elif args.email_command == "imap-test":
            return email_imap_test(args.provider)
        elif args.email_command == "search":
            return email_search(
                args.provider,
                args.folder,
                args.from_,
                args.subject,
                args.since,
                args.limit,
            )
        else:
            email_parser.print_help()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
