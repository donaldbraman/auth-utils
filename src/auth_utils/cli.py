#!/usr/bin/env python3
"""auth-utils CLI for Google OAuth authentication.

Provides centralized authentication commands so sibling repos don't need
to maintain their own login scripts.

Commands:
    auth-utils google login     Interactive OAuth login
    auth-utils google status    Show token status
    auth-utils google refresh   Refresh expired token
    auth-utils google revoke    Revoke and clear token
    auth-utils google setup     Setup guidance
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from auth_utils.google import GoogleOAuth


DEFAULT_SCOPES = ["docs", "drive"]


def _create_auth(scopes: list[str] | None = None) -> GoogleOAuth:
    """Create GoogleOAuth instance with specified scopes."""
    from auth_utils.google import GoogleOAuth

    return GoogleOAuth(scopes=scopes or DEFAULT_SCOPES)


def cmd_login(args: argparse.Namespace) -> int:
    """Interactive OAuth login flow."""
    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES
    auth = _create_auth(scopes)

    # Check if already authorized
    try:
        if auth.is_authorized():
            print("Already authorized with required scopes")
            return cmd_status_impl(auth)
    except FileNotFoundError:
        pass  # Continue to auth flow

    print("=" * 60)
    print("GOOGLE OAUTH LOGIN")
    print("=" * 60)
    print()
    print("Required scopes:")
    for scope in scopes:
        print(f"  - {scope}")
    print()

    # Get authorization URL
    try:
        auth_url = auth.get_authorization_url()
    except FileNotFoundError:
        print("ERROR: credentials.json not found")
        print()
        print("Run 'auth-utils google setup' for instructions.")
        return 1

    print(f"Authorization URL:\n{auth_url}\n")

    if not args.no_browser:
        print("Opening browser...")
        webbrowser.open(auth_url)
    else:
        print("Copy this URL to your browser.")

    print()
    redirect_url = input("Paste redirect URL: ").strip()

    if not redirect_url:
        print("No URL provided, aborting.")
        return 1

    try:
        auth.fetch_token(redirect_url)
        print()
        print("Token saved successfully!")
        return cmd_status_impl(auth)
    except Exception as e:
        print(f"Error: {e}")
        return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show token status."""
    from auth_utils.google.exceptions import CredentialsNotFoundError

    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES
    try:
        auth = _create_auth(scopes)
        return cmd_status_impl(auth)
    except CredentialsNotFoundError:
        print()
        print("Status: No credentials configured")
        print()
        print("Run 'auth-utils google setup' for instructions.")
        return 1


def cmd_status_impl(auth: GoogleOAuth) -> int:
    """Implementation of status display."""
    print()
    try:
        if not auth.is_authorized():
            print("Status: Not authorized")
            print()
            print("Run 'auth-utils google login' to authenticate.")
            return 1

        info = auth.get_token_info()
        print(f"Status:    {info['status']}")
        print(f"Scopes:    {', '.join(info['scopes'])}")
        print(f"Expires:   {info.get('expires_in', 'unknown')}")
        if info.get("last_refresh"):
            print(f"Refreshed: {info['last_refresh']}")
        return 0

    except FileNotFoundError:
        print("Status: No credentials configured")
        print()
        print("Run 'auth-utils google setup' for instructions.")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def cmd_refresh(args: argparse.Namespace) -> int:
    """Refresh existing OAuth token."""
    from auth_utils.google.exceptions import CredentialsNotFoundError

    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES

    try:
        auth = _create_auth(scopes)
    except CredentialsNotFoundError:
        print("No credentials configured.")
        print("Run 'auth-utils google setup' for instructions.")
        return 1

    print("Refreshing token...")

    try:
        if not auth.is_authorized():
            print("No valid token to refresh.")
            print("Run 'auth-utils google login' to authenticate.")
            return 1

        # Force refresh by getting credentials
        auth.get_credentials()
        print("Token refreshed successfully!")
        return cmd_status_impl(auth)

    except FileNotFoundError:
        print("No token found. Please authenticate first.")
        print("Run 'auth-utils google login'")
        return 1
    except Exception as e:
        print(f"Error refreshing token: {e}")
        return 1


def cmd_revoke(args: argparse.Namespace) -> int:
    """Revoke and clear token."""
    from auth_utils.google.exceptions import CredentialsNotFoundError

    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES

    try:
        auth = _create_auth(scopes)
    except CredentialsNotFoundError:
        print("No credentials configured. Nothing to revoke.")
        return 0

    try:
        auth.revoke_token()
        print("Token revoked and cleared.")
        return 0
    except Exception as e:
        print(f"Error revoking token: {e}")
        return 1


def cmd_setup(_args: argparse.Namespace) -> int:
    """Setup guidance for OAuth credentials."""
    print("=" * 60)
    print("GOOGLE OAUTH SETUP")
    print("=" * 60)
    print()
    print("To use Google APIs (Docs, Drive, etc.), you need OAuth 2.0 credentials.")
    print()
    print("Steps:")
    print()
    print("1. Go to: https://console.cloud.google.com/apis/credentials")
    print()
    print("2. Create OAuth 2.0 Client ID:")
    print("   - Click '+ CREATE CREDENTIALS' -> 'OAuth client ID'")
    print("   - Application type: Desktop app")
    print("   - Name: auth-utils (or any name)")
    print()
    print("3. Download the credentials JSON file")
    print()
    print("4. Save it as 'credentials.json' in your project root")
    print()
    print("-" * 60)

    # Check if credentials exist
    creds_path = Path("credentials.json")
    if creds_path.exists():
        print()
        print("credentials.json found!")
        try:
            with open(creds_path) as f:
                creds = json.load(f)
            if "installed" in creds:
                client_id = creds["installed"].get("client_id", "")
                if client_id:
                    print(f"Client ID: {client_id[:40]}...")
                    print()
                    print("Ready to authenticate!")
                    print("Run: auth-utils google login")
                    return 0
        except Exception:
            pass

    print()
    print("credentials.json not found in current directory.")
    print()

    # Offer to open the console
    try:
        response = input("Open Google Cloud Console in browser? (y/n): ").strip().lower()
        if response == "y":
            webbrowser.open("https://console.cloud.google.com/apis/credentials")
            print()
            print("After downloading credentials.json, run:")
            print("  auth-utils google login")
    except (EOFError, KeyboardInterrupt):
        print()

    return 0


def cmd_get_url(args: argparse.Namespace) -> int:
    """Generate OAuth authorization URL without interactive flow."""
    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES
    auth = _create_auth(scopes)

    try:
        url = auth.get_authorization_url()
        print("Authorization URL:")
        print("=" * 60)
        print(url)
        print("=" * 60)
        print()
        print("After authorizing, use 'auth-utils google complete <URL>' to finish.")
        return 0
    except FileNotFoundError:
        print("ERROR: credentials.json not found")
        print("Run 'auth-utils google setup' for instructions.")
        return 1


def cmd_complete(args: argparse.Namespace) -> int:
    """Complete OAuth flow with redirect URL."""
    scopes = args.scopes.split(",") if args.scopes else DEFAULT_SCOPES
    auth = _create_auth(scopes)

    redirect_url = args.redirect_url

    # Parse and validate URL
    parsed = urlparse(redirect_url)
    params = parse_qs(parsed.query)
    code = params.get("code", [None])[0]

    if not code:
        print("ERROR: No authorization code found in URL")
        print()
        print("The redirect URL should contain a 'code' parameter.")
        return 1

    print(f"Authorization code: {code[:20]}...")

    try:
        auth.fetch_token(redirect_url)
        print()
        print("Token saved successfully!")
        return cmd_status_impl(auth)
    except Exception as e:
        print(f"Error: {e}")
        return 1


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog="auth-utils",
        description="Unified authentication utilities for LLM and Google APIs",
    )

    subparsers = parser.add_subparsers(dest="service", help="Service to authenticate")

    # Google subcommand
    google_parser = subparsers.add_parser("google", help="Google OAuth authentication")
    google_subparsers = google_parser.add_subparsers(dest="command", help="Command")

    # Common arguments
    scope_help = "Comma-separated scopes (default: docs,drive)"

    # login
    login_parser = google_subparsers.add_parser("login", help="Interactive OAuth login")
    login_parser.add_argument("--scopes", "-s", help=scope_help)
    login_parser.add_argument(
        "--no-browser", action="store_true", help="Don't open browser automatically"
    )
    login_parser.set_defaults(func=cmd_login)

    # status
    status_parser = google_subparsers.add_parser("status", help="Show token status")
    status_parser.add_argument("--scopes", "-s", help=scope_help)
    status_parser.set_defaults(func=cmd_status)

    # refresh
    refresh_parser = google_subparsers.add_parser("refresh", help="Refresh token")
    refresh_parser.add_argument("--scopes", "-s", help=scope_help)
    refresh_parser.set_defaults(func=cmd_refresh)

    # revoke
    revoke_parser = google_subparsers.add_parser("revoke", help="Revoke token")
    revoke_parser.add_argument("--scopes", "-s", help=scope_help)
    revoke_parser.set_defaults(func=cmd_revoke)

    # setup
    setup_parser = google_subparsers.add_parser("setup", help="Setup guidance")
    setup_parser.set_defaults(func=cmd_setup)

    # get-url
    geturl_parser = google_subparsers.add_parser("get-url", help="Generate authorization URL")
    geturl_parser.add_argument("--scopes", "-s", help=scope_help)
    geturl_parser.set_defaults(func=cmd_get_url)

    # complete
    complete_parser = google_subparsers.add_parser(
        "complete", help="Complete OAuth with redirect URL"
    )
    complete_parser.add_argument("redirect_url", help="Redirect URL from Google OAuth")
    complete_parser.add_argument("--scopes", "-s", help=scope_help)
    complete_parser.set_defaults(func=cmd_complete)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.service:
        parser.print_help()
        return 0

    if args.service == "google" and not args.command:
        # Default to login if no command specified
        args.command = "login"
        args.scopes = None
        args.no_browser = False
        args.func = cmd_login

    if hasattr(args, "func"):
        return args.func(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
