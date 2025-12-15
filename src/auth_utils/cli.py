"""CLI for auth-utils - Google OAuth management.

Usage:
    auth-utils google login [--scopes SCOPES] [--no-browser]
    auth-utils google status
    auth-utils google refresh
    auth-utils google revoke
    auth-utils google setup
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path


def google_login(scopes: list[str], no_browser: bool = False) -> int:
    """Interactive Google OAuth login."""
    from auth_utils.google import CredentialsNotFoundError, GoogleOAuth

    print("=" * 60)
    print("AUTH-UTILS GOOGLE LOGIN")
    print("=" * 60)

    try:
        auth = GoogleOAuth(scopes=scopes)
    except CredentialsNotFoundError:
        print("\nError: credentials.json not found")
        print("Run 'auth-utils google setup' for instructions")
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
    except CredentialsNotFoundError:
        print("credentials.json not found - run 'auth-utils google setup'")
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
    except CredentialsNotFoundError:
        print("credentials.json not found - run 'auth-utils google setup'")
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


def google_setup() -> int:
    """Interactive OAuth setup helper."""
    print("=" * 60)
    print("GOOGLE OAUTH SETUP")
    print("=" * 60)
    print()
    print("To use Google APIs, you need OAuth 2.0 credentials.")
    print()
    print("Steps:")
    print()
    print("1. Go to: https://console.cloud.google.com/apis/credentials")
    print()
    print("2. Create a new OAuth 2.0 Client ID (or use existing)")
    print("   - Application type: Desktop app")
    print("   - Name: auth-utils (or any name)")
    print()
    print("3. Download the credentials JSON")
    print()
    print("4. Save it as 'credentials.json' in your project root")
    print()
    print("-" * 60)

    creds_path = Path("credentials.json")
    if creds_path.exists():
        print()
        print("credentials.json already exists!")
        with open(creds_path) as f:
            creds = json.load(f)
            if "installed" in creds:
                client_id = creds["installed"].get("client_id", "")
                if client_id:
                    print(f"Client ID: {client_id[:30]}...")
                    print()
                    print("You can now run: auth-utils google login")
                    return 0

    print()
    print("credentials.json not found!")
    print()
    print("Please download from Google Cloud Console:")
    print("https://console.cloud.google.com/apis/credentials")
    return 1


def parse_scopes(scope_str: str | None) -> list[str]:
    """Parse comma-separated scopes."""
    if not scope_str:
        return ["docs", "drive"]  # Default scopes
    return [s.strip() for s in scope_str.split(",")]


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="auth-utils",
        description="Authentication utilities for Google OAuth and more",
    )
    subparsers = parser.add_subparsers(dest="service", help="Service to configure")

    # Google subcommand
    google_parser = subparsers.add_parser("google", help="Google OAuth management")
    google_subparsers = google_parser.add_subparsers(dest="command", help="Command")

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

    # google setup
    google_subparsers.add_parser("setup", help="Setup credentials")

    args = parser.parse_args(argv or sys.argv[1:])

    if args.service is None:
        parser.print_help()
        return 0

    if args.service == "google":
        scopes = parse_scopes(getattr(args, "scopes", None))

        if args.command == "login":
            return google_login(scopes, args.no_browser)
        elif args.command == "status":
            return google_status(scopes)
        elif args.command == "refresh":
            return google_refresh(scopes)
        elif args.command == "revoke":
            return google_revoke(scopes)
        elif args.command == "setup":
            return google_setup()
        else:
            google_parser.print_help()
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
