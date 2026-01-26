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
    auth-utils gmail auth                  # Authorize Gmail API access
    auth-utils gmail status                # Show Gmail API authorization status
    auth-utils gmail search <query>        # Search emails via Gmail API
    auth-utils tasks auth                  # Authorize Google Tasks API
    auth-utils tasks status                # Show Tasks authorization status
    auth-utils tasks lists                 # List task lists
    auth-utils tasks list                  # List tasks
    auth-utils tasks add <title>           # Add a task
    auth-utils tasks complete <id>         # Complete a task
    auth-utils calendar auth               # Authorize Google Calendar API
    auth-utils calendar status             # Show Calendar authorization status
    auth-utils calendar list               # List calendars
    auth-utils calendar events             # List upcoming events
    auth-utils calendar add <summary>      # Add an event
    auth-utils drive auth                  # Authorize Google Drive API
    auth-utils drive status                # Show Drive authorization status
    auth-utils drive list                  # List files
    auth-utils drive upload <file>         # Upload a file
    auth-utils drive download <id> <path>  # Download a file
    auth-utils docs auth                   # Authorize Google Docs API
    auth-utils docs status                 # Show Docs authorization status
    auth-utils docs get <id>               # Get document content
    auth-utils docs create <title>         # Create a document
    auth-utils sheets auth                 # Authorize Google Sheets API
    auth-utils sheets status               # Show Sheets authorization status
    auth-utils sheets get <id>             # Get spreadsheet info
    auth-utils sheets read <id> <range>    # Read cell values
    auth-utils sheets write <id> <range>   # Write cell values
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


def email_bulk_send(
    roster_path: str,
    subject: str,
    body: str | None,
    body_file: str | None,
    html: bool,
    from_name: str | None,
    delay: float,
    batch_size: int,
    batch_delay: float,
    dry_run: bool,
) -> int:
    """Send bulk emails with rate limiting."""
    import csv
    from pathlib import Path

    from auth_utils.email import (
        RateLimitConfig,
        SMTPAuthError,
        SMTPClient,
        SMTPConnectionError,
    )

    print("=" * 60)
    print("BULK EMAIL SEND (with rate limiting)")
    print("=" * 60)
    print()

    # Validate inputs
    if not body and not body_file:
        print("Error: Must provide either --body or --body-file")
        return 1

    if body and body_file:
        print("Error: Cannot use both --body and --body-file")
        return 1

    # Load body from file if specified
    if body_file:
        body_path = Path(body_file)
        if not body_path.exists():
            print(f"Error: Body file not found: {body_file}")
            return 1
        body = body_path.read_text()
        print(f"Loaded body from: {body_file}")

    # Load roster
    roster_path_obj = Path(roster_path)
    if not roster_path_obj.exists():
        print(f"Error: Roster file not found: {roster_path}")
        return 1

    try:
        with open(roster_path_obj) as f:
            reader = csv.DictReader(f)
            recipients = list(reader)
    except Exception as e:
        print(f"Error reading roster: {e}")
        return 1

    if not recipients:
        print("Error: No recipients found in roster")
        return 1

    # Check for required 'email' column (case-insensitive)
    first_row = recipients[0]
    email_key = None
    for key in first_row:
        if key.lower() == "email":
            email_key = key
            break

    if not email_key:
        print("Error: Roster must have an 'email' column")
        print(f"Found columns: {list(first_row.keys())}")
        return 1

    # Normalize email key if needed
    if email_key != "email":
        for r in recipients:
            r["email"] = r.pop(email_key)

    print(f"Roster: {roster_path}")
    print(f"Recipients: {len(recipients)}")
    print(f"Subject: {subject}")
    print(f"HTML: {html}")
    if from_name:
        print(f"From name: {from_name}")
    print()

    # Show rate limit settings
    config = RateLimitConfig(
        delay_seconds=delay,
        batch_size=batch_size,
        batch_delay_seconds=batch_delay,
        warn_on_unsafe=True,
    )

    print("Rate limiting:")
    print(f"  Delay between emails: {config.delay_seconds}s")
    print(f"  Batch size: {config.batch_size}")
    print(f"  Batch delay: {config.batch_delay_seconds}s")
    print()

    # Dry run preview
    if dry_run:
        print("=" * 60)
        print("DRY RUN - Preview only, no emails sent")
        print("=" * 60)
        print()

        # Show first 3 recipients
        for i, recipient in enumerate(recipients[:3]):
            try:
                formatted_subject = subject.format(**recipient)
                formatted_body = body.format(**recipient)
                print(f"[{i + 1}] To: {recipient['email']}")
                print(f"    Subject: {formatted_subject}")
                print(f"    Body preview: {formatted_body[:100]}...")
                print()
            except KeyError as e:
                print(f"[{i + 1}] ERROR: Missing template key {e}")
                print(f"    Available keys: {list(recipient.keys())}")
                print()

        if len(recipients) > 3:
            print(f"... and {len(recipients) - 3} more recipients")

        print()
        print("To send for real, remove the --dry-run flag")
        return 0

    # Confirm send
    estimated_time = (
        len(recipients) * config.delay_seconds
        + (len(recipients) // config.batch_size) * config.batch_delay_seconds
    )
    print(f"Estimated time: {estimated_time / 60:.1f} minutes")
    print()

    confirm = input(f"Send {len(recipients)} emails? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return 0

    # Send emails
    try:
        client = SMTPClient(provider="gmail")
        print(f"\nSending as: {client.user}")
        print()

        def on_progress(sent: int, total: int, email: str) -> None:
            print(f"[{sent}/{total}] Sent to {email}")

        def on_error(email: str, error_type: str, exc: Exception) -> None:
            print(f"FAILED: {email} - {error_type}: {exc}")

        result = client.send_bulk(
            recipients=recipients,
            subject=subject,
            body_template=body,
            html=html,
            from_name=from_name,
            rate_limit=config,
            on_progress=on_progress,
            on_error=on_error,
        )

        return 0 if result.failed == 0 else 1

    except SMTPAuthError as e:
        print(f"\nAuthentication error: {e}")
        print("\nTips:")
        print("  - Ensure 2-Step Verification is enabled")
        print("  - Generate an App Password")
        return 1

    except SMTPConnectionError as e:
        print(f"\nConnection error: {e}")
        print("\nThis may indicate rate limiting. Wait 1-24 hours and retry.")
        return 1

    except Exception as e:
        print(f"\nError: {e}")
        return 1


# =============================================================================
# Gmail API Commands
# =============================================================================


def gmail_auth() -> int:
    """Authorize Gmail API access via OAuth."""
    from auth_utils.gmail import GmailClient
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError

    print("=" * 60)
    print("GMAIL API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = GmailClient()

        if client.is_authorized():
            print("Already authorized!")
            print(f"User: {client.user_email}")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        print(f"User: {client.user_email}")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes gmail_readonly'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def gmail_status() -> int:
    """Show Gmail API authorization status."""
    from auth_utils.gmail import GmailClient

    print("=" * 60)
    print("GMAIL API STATUS")
    print("=" * 60)
    print()

    try:
        client = GmailClient()

        if client.is_authorized():
            print("[x] Authorized")
            print(f"    User: {client.user_email}")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils gmail auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def gmail_search(query: str, limit: int) -> int:
    """Search emails via Gmail API."""
    from auth_utils.gmail import GmailClient
    from auth_utils.google.exceptions import AuthorizationRequired

    print("=" * 60)
    print("SEARCHING EMAILS VIA GMAIL API")
    print("=" * 60)
    print()

    try:
        client = GmailClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils gmail auth' first.")
            return 1

        print(f"User: {client.user_email}")
        print(f"Query: {query or '(all messages)'}")
        print()

        messages = client.search(query=query, max_results=limit)

        if not messages:
            print("No messages found.")
            return 0

        print(f"Found {len(messages)} message(s):\n")
        for msg in messages:
            date_str = msg.date.strftime("%Y-%m-%d %H:%M") if msg.date else "unknown"
            print(f"  [{date_str}] {msg.sender}")
            print(f"    Subject: {msg.subject}")
            print(f"    Preview: {msg.snippet[:80]}...")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils gmail auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Google Tasks Commands
# =============================================================================


def tasks_auth() -> int:
    """Authorize Google Tasks API access via OAuth."""
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError
    from auth_utils.tasks import TasksClient

    print("=" * 60)
    print("GOOGLE TASKS API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = TasksClient()

        if client.is_authorized():
            print("Already authorized!")
            lists = client.list_task_lists()
            print(f"Found {len(lists)} task list(s)")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        lists = client.list_task_lists()
        print(f"Found {len(lists)} task list(s)")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes tasks'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def tasks_status() -> int:
    """Show Google Tasks API authorization status."""
    from auth_utils.tasks import TasksClient

    print("=" * 60)
    print("GOOGLE TASKS API STATUS")
    print("=" * 60)
    print()

    try:
        client = TasksClient()

        if client.is_authorized():
            print("[x] Authorized")
            lists = client.list_task_lists()
            print(f"    Task lists: {len(lists)}")
            for tl in lists[:5]:
                print(f"      - {tl.title}")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils tasks auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def tasks_lists() -> int:
    """List all task lists."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.tasks import TasksClient

    try:
        client = TasksClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils tasks auth' first.")
            return 1

        lists = client.list_task_lists()

        if not lists:
            print("No task lists found.")
            return 0

        print(f"Found {len(lists)} task list(s):\n")
        for tl in lists:
            print(f"  {tl.id}")
            print(f"    Title: {tl.title}")
            if tl.updated:
                print(f"    Updated: {tl.updated.strftime('%Y-%m-%d %H:%M')}")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils tasks auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def tasks_list(tasklist_id: str, show_completed: bool) -> int:
    """List tasks in a task list."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.tasks import TasksClient

    try:
        client = TasksClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils tasks auth' first.")
            return 1

        tasks = client.list_tasks(tasklist_id=tasklist_id, show_completed=show_completed)

        if not tasks:
            print("No tasks found.")
            return 0

        print(f"Found {len(tasks)} task(s):\n")
        for task in tasks:
            status = "[x]" if task.is_completed else "[ ]"
            due_str = f" (due: {task.due})" if task.due else ""
            print(f"  {status} {task.title}{due_str}")
            print(f"      ID: {task.id}")
            if task.notes:
                print(f"      Notes: {task.notes[:50]}...")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils tasks auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def tasks_add(title: str, tasklist_id: str, notes: str | None, due: str | None) -> int:
    """Add a new task."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.tasks import TasksClient

    try:
        client = TasksClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils tasks auth' first.")
            return 1

        task = client.create_task(
            title=title,
            tasklist_id=tasklist_id,
            notes=notes,
            due=due,
        )

        print(f"Task created: {task.title}")
        print(f"  ID: {task.id}")
        if task.due:
            print(f"  Due: {task.due}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils tasks auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def tasks_complete(task_id: str, tasklist_id: str) -> int:
    """Complete a task."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.tasks import TasksClient

    try:
        client = TasksClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils tasks auth' first.")
            return 1

        task = client.complete_task(task_id=task_id, tasklist_id=tasklist_id)
        print(f"Task completed: {task.title}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils tasks auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def tasks_delete(task_id: str, tasklist_id: str) -> int:
    """Delete a task."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.tasks import TasksClient

    try:
        client = TasksClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils tasks auth' first.")
            return 1

        if client.delete_task(task_id=task_id, tasklist_id=tasklist_id):
            print("Task deleted.")
        else:
            print("Failed to delete task.")
            return 1

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils tasks auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Google Calendar Commands
# =============================================================================


def calendar_auth() -> int:
    """Authorize Google Calendar API access via OAuth."""
    from auth_utils.calendar import CalendarClient
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError

    print("=" * 60)
    print("GOOGLE CALENDAR API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = CalendarClient()

        if client.is_authorized():
            print("Already authorized!")
            calendars = client.list_calendars()
            print(f"Found {len(calendars)} calendar(s)")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        calendars = client.list_calendars()
        print(f"Found {len(calendars)} calendar(s)")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes calendar'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def calendar_status() -> int:
    """Show Google Calendar API authorization status."""
    from auth_utils.calendar import CalendarClient

    print("=" * 60)
    print("GOOGLE CALENDAR API STATUS")
    print("=" * 60)
    print()

    try:
        client = CalendarClient()

        if client.is_authorized():
            print("[x] Authorized")
            calendars = client.list_calendars()
            print(f"    Calendars: {len(calendars)}")
            for cal in calendars[:5]:
                primary = " (primary)" if cal.primary else ""
                print(f"      - {cal.summary}{primary}")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils calendar auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def calendar_list() -> int:
    """List all calendars."""
    from auth_utils.calendar import CalendarClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = CalendarClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils calendar auth' first.")
            return 1

        calendars = client.list_calendars()

        if not calendars:
            print("No calendars found.")
            return 0

        print(f"Found {len(calendars)} calendar(s):\n")
        for cal in calendars:
            primary = " (primary)" if cal.primary else ""
            print(f"  {cal.id}")
            print(f"    Name: {cal.summary}{primary}")
            if cal.description:
                print(f"    Description: {cal.description[:50]}...")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils calendar auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def calendar_events(calendar_id: str, limit: int) -> int:
    """List upcoming events."""
    from auth_utils.calendar import CalendarClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = CalendarClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils calendar auth' first.")
            return 1

        events = client.list_events(calendar_id=calendar_id, max_results=limit)

        if not events:
            print("No upcoming events found.")
            return 0

        print(f"Found {len(events)} upcoming event(s):\n")
        for event in events:
            start_str = event.start.strftime("%Y-%m-%d %H:%M") if event.start else "unknown"
            print(f"  [{start_str}] {event.summary}")
            print(f"      ID: {event.id}")
            if event.location:
                print(f"      Location: {event.location}")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils calendar auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def calendar_add(
    summary: str,
    start: str,
    end: str | None,
    calendar_id: str,
    description: str | None,
    location: str | None,
) -> int:
    """Add a calendar event."""
    from auth_utils.calendar import CalendarClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = CalendarClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils calendar auth' first.")
            return 1

        event = client.create_event(
            summary=summary,
            start=start,
            end=end,
            calendar_id=calendar_id,
            description=description,
            location=location,
        )

        print(f"Event created: {event.summary}")
        print(f"  ID: {event.id}")
        if event.start:
            print(f"  Start: {event.start}")
        if event.html_link:
            print(f"  Link: {event.html_link}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils calendar auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def calendar_delete(event_id: str, calendar_id: str) -> int:
    """Delete a calendar event."""
    from auth_utils.calendar import CalendarClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = CalendarClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils calendar auth' first.")
            return 1

        if client.delete_event(event_id=event_id, calendar_id=calendar_id):
            print("Event deleted.")
        else:
            print("Failed to delete event.")
            return 1

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils calendar auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Google Drive Commands
# =============================================================================


def drive_auth() -> int:
    """Authorize Google Drive API access via OAuth."""
    from auth_utils.drive import DriveClient
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError

    print("=" * 60)
    print("GOOGLE DRIVE API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = DriveClient()

        if client.is_authorized():
            print("Already authorized!")
            files = client.list_files(max_results=5)
            print(f"Found {len(files)}+ files")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        files = client.list_files(max_results=5)
        print(f"Found {len(files)}+ files")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes drive'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def drive_status() -> int:
    """Show Google Drive API authorization status."""
    from auth_utils.drive import DriveClient

    print("=" * 60)
    print("GOOGLE DRIVE API STATUS")
    print("=" * 60)
    print()

    try:
        client = DriveClient()

        if client.is_authorized():
            print("[x] Authorized")
            files = client.list_files(max_results=5)
            print(f"    Recent files: {len(files)}+")
            for f in files[:3]:
                icon = "/" if f.is_folder else " "
                print(f"      {icon} {f.name}")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils drive auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def drive_list(folder_id: str | None, limit: int, query: str | None) -> int:
    """List files in Drive."""
    from auth_utils.drive import DriveClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DriveClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils drive auth' first.")
            return 1

        files = client.list_files(folder_id=folder_id, max_results=limit, query=query)

        if not files:
            print("No files found.")
            return 0

        print(f"Found {len(files)} file(s):\n")
        for f in files:
            icon = "/" if f.is_folder else " "
            size_str = f" ({f.size} bytes)" if f.size else ""
            print(f"  {icon} {f.name}{size_str}")
            print(f"      ID: {f.id}")
            if f.modified_time:
                print(f"      Modified: {f.modified_time.strftime('%Y-%m-%d %H:%M')}")
            print()

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils drive auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def drive_upload(file_path: str, name: str | None, folder_id: str | None) -> int:
    """Upload a file to Drive."""
    from auth_utils.drive import DriveClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DriveClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils drive auth' first.")
            return 1

        path = Path(file_path)
        if not path.exists():
            print(f"Error: File not found: {file_path}")
            return 1

        upload_name = name or path.name
        print(f"Uploading {path.name}...", end=" ", flush=True)

        uploaded = client.upload_file(
            name=upload_name,
            file_path=path,
            folder_id=folder_id,
        )

        print("[OK]")
        print(f"  Name: {uploaded.name}")
        print(f"  ID: {uploaded.id}")
        if uploaded.web_view_link:
            print(f"  Link: {uploaded.web_view_link}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils drive auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def drive_download(file_id: str, output_path: str) -> int:
    """Download a file from Drive."""
    from auth_utils.drive import DriveClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DriveClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils drive auth' first.")
            return 1

        # Get file info
        file_info = client.get_file(file_id)
        if not file_info:
            print(f"Error: File not found: {file_id}")
            return 1

        print(f"Downloading {file_info.name}...", end=" ", flush=True)

        if client.download_file(file_id, output_path):
            print("[OK]")
            print(f"  Saved to: {output_path}")
            return 0
        else:
            print("[FAILED]")
            return 1

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils drive auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def drive_delete(file_id: str) -> int:
    """Delete a file from Drive."""
    from auth_utils.drive import DriveClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DriveClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils drive auth' first.")
            return 1

        if client.delete_file(file_id):
            print("File deleted.")
        else:
            print("Failed to delete file.")
            return 1

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils drive auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Google Docs Commands
# =============================================================================


def docs_auth() -> int:
    """Authorize Google Docs API access via OAuth."""
    from auth_utils.docs import DocsClient
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError

    print("=" * 60)
    print("GOOGLE DOCS API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = DocsClient()

        if client.is_authorized():
            print("Already authorized!")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes docs,drive_file'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def docs_status() -> int:
    """Show Google Docs API authorization status."""
    from auth_utils.docs import DocsClient

    print("=" * 60)
    print("GOOGLE DOCS API STATUS")
    print("=" * 60)
    print()

    try:
        client = DocsClient()

        if client.is_authorized():
            print("[x] Authorized")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils docs auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def docs_get(document_id: str) -> int:
    """Get document content."""
    from auth_utils.docs import DocsClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DocsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils docs auth' first.")
            return 1

        doc = client.get_document(document_id)

        if not doc:
            print(f"Error: Document not found: {document_id}")
            return 1

        print(f"Title: {doc.title}")
        print(f"ID: {doc.id}")
        print(f"Words: ~{doc.word_count}")
        print()
        print("Content:")
        print("-" * 40)
        print(doc.body_text[:2000])
        if len(doc.body_text) > 2000:
            print(f"\n... ({len(doc.body_text) - 2000} more characters)")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils docs auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def docs_create(title: str, body: str | None) -> int:
    """Create a new document."""
    from auth_utils.docs import DocsClient
    from auth_utils.google.exceptions import AuthorizationRequired

    try:
        client = DocsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils docs auth' first.")
            return 1

        doc = client.create_document(title=title, body_text=body)

        print(f"Document created: {doc.title}")
        print(f"  ID: {doc.id}")
        print(f"  URL: https://docs.google.com/document/d/{doc.id}/edit")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils docs auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


# =============================================================================
# Google Sheets Commands
# =============================================================================


def sheets_auth() -> int:
    """Authorize Google Sheets API access via OAuth."""
    from auth_utils.google.exceptions import AuthorizationRequired, TokenError
    from auth_utils.sheets import SheetsClient

    print("=" * 60)
    print("GOOGLE SHEETS API AUTHORIZATION")
    print("=" * 60)
    print()

    try:
        client = SheetsClient()

        if client.is_authorized():
            print("Already authorized!")
            return 0

        print("Opening browser for OAuth authorization...")
        print()
        client.authorize()
        print()
        print("Authorization successful!")
        return 0

    except AuthorizationRequired as e:
        print("Could not open browser automatically.")
        print(f"\nVisit this URL to authorize:\n{e.auth_url}")
        print("\nThen run 'auth-utils google login --scopes sheets,drive_file'")
        return 1

    except TokenError as e:
        print(f"Authorization failed: {e}")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def sheets_status() -> int:
    """Show Google Sheets API authorization status."""
    from auth_utils.sheets import SheetsClient

    print("=" * 60)
    print("GOOGLE SHEETS API STATUS")
    print("=" * 60)
    print()

    try:
        client = SheetsClient()

        if client.is_authorized():
            print("[x] Authorized")
        else:
            print("[ ] Not authorized")
            print("    Run 'auth-utils sheets auth' to authorize")

        return 0

    except Exception as e:
        print(f"[ ] Error checking status: {e}")
        return 1


def sheets_get(spreadsheet_id: str) -> int:
    """Get spreadsheet info."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.sheets import SheetsClient

    try:
        client = SheetsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils sheets auth' first.")
            return 1

        spreadsheet = client.get_spreadsheet(spreadsheet_id)

        if not spreadsheet:
            print(f"Error: Spreadsheet not found: {spreadsheet_id}")
            return 1

        print(f"Title: {spreadsheet.title}")
        print(f"ID: {spreadsheet.id}")
        if spreadsheet.url:
            print(f"URL: {spreadsheet.url}")
        print()
        print("Sheets:")
        for sheet in spreadsheet.sheets or []:
            print(f"  - {sheet.title} ({sheet.row_count}x{sheet.column_count})")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils sheets auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def sheets_read(spreadsheet_id: str, range_notation: str) -> int:
    """Read values from a range."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.sheets import SheetsClient

    try:
        client = SheetsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils sheets auth' first.")
            return 1

        values = client.read_range(spreadsheet_id, range_notation)

        if not values:
            print("No data found in range.")
            return 0

        print(f"Range: {range_notation}")
        print(f"Rows: {len(values)}")
        print()
        for i, row in enumerate(values[:20]):
            row_str = " | ".join(str(cell) for cell in row)
            print(f"  {i + 1}: {row_str}")
        if len(values) > 20:
            print(f"  ... ({len(values) - 20} more rows)")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils sheets auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def sheets_write(spreadsheet_id: str, range_notation: str, values_str: str) -> int:
    """Write values to a range."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.sheets import SheetsClient

    try:
        client = SheetsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils sheets auth' first.")
            return 1

        # Parse values (comma-separated, semicolon for rows)
        # e.g., "a,b,c;d,e,f" -> [["a","b","c"],["d","e","f"]]
        rows = values_str.split(";")
        values = [row.split(",") for row in rows]

        cells_updated = client.write_range(spreadsheet_id, range_notation, values)

        print(f"Updated {cells_updated} cell(s) at {range_notation}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils sheets auth' first.")
        return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def sheets_create(title: str) -> int:
    """Create a new spreadsheet."""
    from auth_utils.google.exceptions import AuthorizationRequired
    from auth_utils.sheets import SheetsClient

    try:
        client = SheetsClient()

        if not client.is_authorized():
            print("Not authorized. Run 'auth-utils sheets auth' first.")
            return 1

        spreadsheet = client.create_spreadsheet(title=title)

        print(f"Spreadsheet created: {spreadsheet.title}")
        print(f"  ID: {spreadsheet.id}")
        if spreadsheet.url:
            print(f"  URL: {spreadsheet.url}")

        return 0

    except AuthorizationRequired:
        print("Not authorized. Run 'auth-utils sheets auth' first.")
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

    # email bulk-send
    email_bulk_parser = email_subparsers.add_parser(
        "bulk-send", help="Send bulk emails with rate limiting"
    )
    email_bulk_parser.add_argument(
        "--roster",
        type=str,
        required=True,
        help="Path to CSV file with 'email' column (and optional personalization columns)",
    )
    email_bulk_parser.add_argument(
        "--subject",
        type=str,
        required=True,
        help="Email subject (use {column_name} for personalization)",
    )
    email_bulk_parser.add_argument(
        "--body",
        type=str,
        help="Email body text (use {column_name} for personalization)",
    )
    email_bulk_parser.add_argument(
        "--body-file",
        type=str,
        help="Path to file containing email body (HTML or text)",
    )
    email_bulk_parser.add_argument(
        "--html",
        action="store_true",
        help="Send as HTML email",
    )
    email_bulk_parser.add_argument(
        "--from-name",
        type=str,
        help="Display name for sender (e.g., 'Professor Smith')",
    )
    email_bulk_parser.add_argument(
        "--delay",
        type=float,
        default=10,
        help="Seconds between emails (default: 10, min: 3)",
    )
    email_bulk_parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Emails per batch before longer pause (default: 50)",
    )
    email_bulk_parser.add_argument(
        "--batch-delay",
        type=float,
        default=60,
        help="Seconds between batches (default: 60)",
    )
    email_bulk_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview emails without sending",
    )

    # Gmail API subcommand
    gmail_parser = subparsers.add_parser("gmail", help="Gmail API management")
    gmail_subparsers = gmail_parser.add_subparsers(dest="gmail_command", help="Command")

    # gmail auth
    gmail_subparsers.add_parser("auth", help="Authorize Gmail API access")

    # gmail status
    gmail_subparsers.add_parser("status", help="Show Gmail API authorization status")

    # gmail search
    gmail_search_parser = gmail_subparsers.add_parser("search", help="Search emails via Gmail API")
    gmail_search_parser.add_argument(
        "query",
        nargs="?",
        default="",
        help="Gmail search query (e.g., 'from:user@example.com subject:test')",
    )
    gmail_search_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max messages to return (default: 10)",
    )

    # Tasks API subcommand
    tasks_parser = subparsers.add_parser("tasks", help="Google Tasks management")
    tasks_subparsers = tasks_parser.add_subparsers(dest="tasks_command", help="Command")

    # tasks auth
    tasks_subparsers.add_parser("auth", help="Authorize Google Tasks API")

    # tasks status
    tasks_subparsers.add_parser("status", help="Show Tasks authorization status")

    # tasks lists
    tasks_subparsers.add_parser("lists", help="List all task lists")

    # tasks list
    tasks_list_parser = tasks_subparsers.add_parser("list", help="List tasks")
    tasks_list_parser.add_argument(
        "--tasklist",
        type=str,
        default="@default",
        help="Task list ID (default: @default)",
    )
    tasks_list_parser.add_argument(
        "--show-completed",
        action="store_true",
        default=True,
        help="Include completed tasks (default: True)",
    )

    # tasks add
    tasks_add_parser = tasks_subparsers.add_parser("add", help="Add a task")
    tasks_add_parser.add_argument("title", help="Task title")
    tasks_add_parser.add_argument(
        "--tasklist",
        type=str,
        default="@default",
        help="Task list ID (default: @default)",
    )
    tasks_add_parser.add_argument(
        "--notes",
        type=str,
        help="Task notes/description",
    )
    tasks_add_parser.add_argument(
        "--due",
        type=str,
        help="Due date (YYYY-MM-DD)",
    )

    # tasks complete
    tasks_complete_parser = tasks_subparsers.add_parser("complete", help="Complete a task")
    tasks_complete_parser.add_argument("task_id", help="Task ID to complete")
    tasks_complete_parser.add_argument(
        "--tasklist",
        type=str,
        default="@default",
        help="Task list ID (default: @default)",
    )

    # tasks delete
    tasks_delete_parser = tasks_subparsers.add_parser("delete", help="Delete a task")
    tasks_delete_parser.add_argument("task_id", help="Task ID to delete")
    tasks_delete_parser.add_argument(
        "--tasklist",
        type=str,
        default="@default",
        help="Task list ID (default: @default)",
    )

    # Calendar API subcommand
    calendar_parser = subparsers.add_parser("calendar", help="Google Calendar management")
    calendar_subparsers = calendar_parser.add_subparsers(dest="calendar_command", help="Command")

    # calendar auth
    calendar_subparsers.add_parser("auth", help="Authorize Google Calendar API")

    # calendar status
    calendar_subparsers.add_parser("status", help="Show Calendar authorization status")

    # calendar list
    calendar_subparsers.add_parser("list", help="List all calendars")

    # calendar events
    calendar_events_parser = calendar_subparsers.add_parser("events", help="List upcoming events")
    calendar_events_parser.add_argument(
        "--calendar",
        type=str,
        default="primary",
        help="Calendar ID (default: primary)",
    )
    calendar_events_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Max events to return (default: 10)",
    )

    # calendar add
    calendar_add_parser = calendar_subparsers.add_parser("add", help="Add an event")
    calendar_add_parser.add_argument("summary", help="Event title")
    calendar_add_parser.add_argument("start", help="Start time (ISO format: YYYY-MM-DDTHH:MM:SS)")
    calendar_add_parser.add_argument(
        "--end",
        type=str,
        help="End time (defaults to 1 hour after start)",
    )
    calendar_add_parser.add_argument(
        "--calendar",
        type=str,
        default="primary",
        help="Calendar ID (default: primary)",
    )
    calendar_add_parser.add_argument(
        "--description",
        type=str,
        help="Event description",
    )
    calendar_add_parser.add_argument(
        "--location",
        type=str,
        help="Event location",
    )

    # calendar delete
    calendar_delete_parser = calendar_subparsers.add_parser("delete", help="Delete an event")
    calendar_delete_parser.add_argument("event_id", help="Event ID to delete")
    calendar_delete_parser.add_argument(
        "--calendar",
        type=str,
        default="primary",
        help="Calendar ID (default: primary)",
    )

    # Drive API subcommand
    drive_parser = subparsers.add_parser("drive", help="Google Drive management")
    drive_subparsers = drive_parser.add_subparsers(dest="drive_command", help="Command")

    # drive auth
    drive_subparsers.add_parser("auth", help="Authorize Google Drive API")

    # drive status
    drive_subparsers.add_parser("status", help="Show Drive authorization status")

    # drive list
    drive_list_parser = drive_subparsers.add_parser("list", help="List files")
    drive_list_parser.add_argument(
        "--folder",
        type=str,
        help="Folder ID to list files in",
    )
    drive_list_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max files to return (default: 20)",
    )
    drive_list_parser.add_argument(
        "--query",
        type=str,
        help="Search query (Drive query syntax)",
    )

    # drive upload
    drive_upload_parser = drive_subparsers.add_parser("upload", help="Upload a file")
    drive_upload_parser.add_argument("file", help="Local file path to upload")
    drive_upload_parser.add_argument(
        "--name",
        type=str,
        help="Name for file in Drive (defaults to local filename)",
    )
    drive_upload_parser.add_argument(
        "--folder",
        type=str,
        help="Destination folder ID",
    )

    # drive download
    drive_download_parser = drive_subparsers.add_parser("download", help="Download a file")
    drive_download_parser.add_argument("file_id", help="Drive file ID")
    drive_download_parser.add_argument("output", help="Local output path")

    # drive delete
    drive_delete_parser = drive_subparsers.add_parser("delete", help="Delete a file")
    drive_delete_parser.add_argument("file_id", help="Drive file ID to delete")

    # Docs API subcommand
    docs_parser = subparsers.add_parser("docs", help="Google Docs management")
    docs_subparsers = docs_parser.add_subparsers(dest="docs_command", help="Command")

    # docs auth
    docs_subparsers.add_parser("auth", help="Authorize Google Docs API")

    # docs status
    docs_subparsers.add_parser("status", help="Show Docs authorization status")

    # docs get
    docs_get_parser = docs_subparsers.add_parser("get", help="Get document content")
    docs_get_parser.add_argument("document_id", help="Document ID")

    # docs create
    docs_create_parser = docs_subparsers.add_parser("create", help="Create a document")
    docs_create_parser.add_argument("title", help="Document title")
    docs_create_parser.add_argument(
        "--body",
        type=str,
        help="Initial body text",
    )

    # Sheets API subcommand
    sheets_parser = subparsers.add_parser("sheets", help="Google Sheets management")
    sheets_subparsers = sheets_parser.add_subparsers(dest="sheets_command", help="Command")

    # sheets auth
    sheets_subparsers.add_parser("auth", help="Authorize Google Sheets API")

    # sheets status
    sheets_subparsers.add_parser("status", help="Show Sheets authorization status")

    # sheets get
    sheets_get_parser = sheets_subparsers.add_parser("get", help="Get spreadsheet info")
    sheets_get_parser.add_argument("spreadsheet_id", help="Spreadsheet ID")

    # sheets read
    sheets_read_parser = sheets_subparsers.add_parser("read", help="Read values from a range")
    sheets_read_parser.add_argument("spreadsheet_id", help="Spreadsheet ID")
    sheets_read_parser.add_argument("range", help="Range in A1 notation (e.g., Sheet1!A1:C10)")

    # sheets write
    sheets_write_parser = sheets_subparsers.add_parser("write", help="Write values to a range")
    sheets_write_parser.add_argument("spreadsheet_id", help="Spreadsheet ID")
    sheets_write_parser.add_argument("range", help="Range in A1 notation (e.g., Sheet1!A1)")
    sheets_write_parser.add_argument(
        "values",
        help="Values to write (comma-separated, semicolon for rows: a,b,c;d,e,f)",
    )

    # sheets create
    sheets_create_parser = sheets_subparsers.add_parser("create", help="Create a spreadsheet")
    sheets_create_parser.add_argument("title", help="Spreadsheet title")

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
        elif args.email_command == "bulk-send":
            return email_bulk_send(
                roster_path=args.roster,
                subject=args.subject,
                body=args.body,
                body_file=args.body_file,
                html=args.html,
                from_name=args.from_name,
                delay=args.delay,
                batch_size=args.batch_size,
                batch_delay=args.batch_delay,
                dry_run=args.dry_run,
            )
        else:
            email_parser.print_help()
            return 0

    if args.command == "gmail":
        if args.gmail_command == "auth":
            return gmail_auth()
        elif args.gmail_command == "status":
            return gmail_status()
        elif args.gmail_command == "search":
            return gmail_search(args.query, args.limit)
        else:
            gmail_parser.print_help()
            return 0

    if args.command == "tasks":
        if args.tasks_command == "auth":
            return tasks_auth()
        elif args.tasks_command == "status":
            return tasks_status()
        elif args.tasks_command == "lists":
            return tasks_lists()
        elif args.tasks_command == "list":
            return tasks_list(args.tasklist, args.show_completed)
        elif args.tasks_command == "add":
            return tasks_add(args.title, args.tasklist, args.notes, args.due)
        elif args.tasks_command == "complete":
            return tasks_complete(args.task_id, args.tasklist)
        elif args.tasks_command == "delete":
            return tasks_delete(args.task_id, args.tasklist)
        else:
            tasks_parser.print_help()
            return 0

    if args.command == "calendar":
        if args.calendar_command == "auth":
            return calendar_auth()
        elif args.calendar_command == "status":
            return calendar_status()
        elif args.calendar_command == "list":
            return calendar_list()
        elif args.calendar_command == "events":
            return calendar_events(args.calendar, args.limit)
        elif args.calendar_command == "add":
            return calendar_add(
                args.summary,
                args.start,
                args.end,
                args.calendar,
                args.description,
                args.location,
            )
        elif args.calendar_command == "delete":
            return calendar_delete(args.event_id, args.calendar)
        else:
            calendar_parser.print_help()
            return 0

    if args.command == "drive":
        if args.drive_command == "auth":
            return drive_auth()
        elif args.drive_command == "status":
            return drive_status()
        elif args.drive_command == "list":
            return drive_list(args.folder, args.limit, args.query)
        elif args.drive_command == "upload":
            return drive_upload(args.file, args.name, args.folder)
        elif args.drive_command == "download":
            return drive_download(args.file_id, args.output)
        elif args.drive_command == "delete":
            return drive_delete(args.file_id)
        else:
            drive_parser.print_help()
            return 0

    if args.command == "docs":
        if args.docs_command == "auth":
            return docs_auth()
        elif args.docs_command == "status":
            return docs_status()
        elif args.docs_command == "get":
            return docs_get(args.document_id)
        elif args.docs_command == "create":
            return docs_create(args.title, args.body)
        else:
            docs_parser.print_help()
            return 0

    if args.command == "sheets":
        if args.sheets_command == "auth":
            return sheets_auth()
        elif args.sheets_command == "status":
            return sheets_status()
        elif args.sheets_command == "get":
            return sheets_get(args.spreadsheet_id)
        elif args.sheets_command == "read":
            return sheets_read(args.spreadsheet_id, args.range)
        elif args.sheets_command == "write":
            return sheets_write(args.spreadsheet_id, args.range, args.values)
        elif args.sheets_command == "create":
            return sheets_create(args.title)
        else:
            sheets_parser.print_help()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
