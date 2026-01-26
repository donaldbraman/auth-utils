"""SMTP client for sending emails."""

from __future__ import annotations

import smtplib
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

from auth_utils.email.exceptions import (
    SMTPAuthError,
    SMTPConnectionError,
    SMTPSendError,
)
from auth_utils.email.providers.gmail import GmailProvider

if TYPE_CHECKING:
    from auth_utils.email.providers.base import BaseSMTPProvider

# Provider registry
PROVIDERS: dict[str, type[BaseSMTPProvider]] = {
    "gmail": GmailProvider,
}


# =============================================================================
# CONSERVATIVE RATE LIMITING DEFAULTS
# =============================================================================
# These defaults are based on Gmail best practices to avoid rate limiting:
# - Gmail rate limits: ~20 emails/hour safe threshold
# - Daily limit: 2,000 for Google Workspace, 500 for free Gmail
# - Sending too fast triggers temporary bans (1-24 hours)
#
# WARNING: Overriding these defaults may result in your account being
# temporarily suspended by Gmail. Use at your own risk.
# =============================================================================

# Safe defaults based on Gmail best practices
DEFAULT_DELAY_SECONDS = 10  # 10 seconds between emails (safe: ~6/minute)
DEFAULT_BATCH_SIZE = 50  # Maximum emails per batch before longer pause
DEFAULT_BATCH_DELAY_SECONDS = 60  # 1 minute pause between batches
SAFE_HOURLY_LIMIT = 20  # Gmail's safe hourly threshold

# Minimum values to prevent abuse
MIN_DELAY_SECONDS = 3  # Absolute minimum delay
MIN_BATCH_DELAY_SECONDS = 30  # Minimum pause between batches


@dataclass
class RateLimitConfig:
    """Configuration for email rate limiting.

    Conservative defaults are set to prevent Gmail rate limit bans.
    Override at your own risk - aggressive sending can result in
    temporary account suspension.

    Attributes:
        delay_seconds: Seconds to wait between individual emails.
            Default: 10 seconds (safe for ~6 emails/minute)
        batch_size: Number of emails per batch before taking a longer pause.
            Default: 50 emails
        batch_delay_seconds: Seconds to wait between batches.
            Default: 60 seconds (1 minute)
        warn_on_unsafe: Whether to print warnings when using unsafe settings.
            Default: True
    """

    delay_seconds: float = DEFAULT_DELAY_SECONDS
    batch_size: int = DEFAULT_BATCH_SIZE
    batch_delay_seconds: float = DEFAULT_BATCH_DELAY_SECONDS
    warn_on_unsafe: bool = True
    _warnings_shown: set[str] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        """Validate configuration and warn about unsafe settings."""
        if self.warn_on_unsafe:
            self._check_and_warn()

    def _check_and_warn(self) -> None:
        """Check settings and emit loud warnings for unsafe values."""
        warnings_to_show = []

        if self.delay_seconds < DEFAULT_DELAY_SECONDS:
            warnings_to_show.append(
                f"⚠️  WARNING: delay_seconds={self.delay_seconds}s is below the safe "
                f"default of {DEFAULT_DELAY_SECONDS}s.\n"
                f"   Gmail may rate-limit or suspend your account with aggressive sending."
            )

        if self.delay_seconds < MIN_DELAY_SECONDS:
            warnings_to_show.append(
                f"🚨 DANGER: delay_seconds={self.delay_seconds}s is VERY LOW!\n"
                f"   Minimum recommended: {MIN_DELAY_SECONDS}s. You risk immediate rate limiting."
            )

        if self.batch_size > DEFAULT_BATCH_SIZE:
            warnings_to_show.append(
                f"⚠️  WARNING: batch_size={self.batch_size} exceeds the safe "
                f"default of {DEFAULT_BATCH_SIZE}.\n"
                f"   Consider smaller batches to avoid triggering rate limits."
            )

        if self.batch_delay_seconds < DEFAULT_BATCH_DELAY_SECONDS:
            warnings_to_show.append(
                f"⚠️  WARNING: batch_delay_seconds={self.batch_delay_seconds}s is below "
                f"the safe default of {DEFAULT_BATCH_DELAY_SECONDS}s.\n"
                f"   Longer pauses between batches help avoid rate limits."
            )

        # Calculate estimated hourly rate
        emails_per_hour = 3600 / self.delay_seconds if self.delay_seconds > 0 else float("inf")
        if emails_per_hour > SAFE_HOURLY_LIMIT:
            warnings_to_show.append(
                f"⚠️  WARNING: Current settings allow ~{emails_per_hour:.0f} emails/hour.\n"
                f"   Gmail's safe threshold is ~{SAFE_HOURLY_LIMIT}/hour. "
                f"You may be rate-limited."
            )

        # Show warnings (only once per unique message)
        for warning in warnings_to_show:
            if warning not in self._warnings_shown:
                self._warnings_shown.add(warning)
                print(f"\n{warning}\n", file=sys.stderr)

    @classmethod
    def conservative(cls) -> RateLimitConfig:
        """Create a configuration with conservative (safe) defaults."""
        return cls()

    @classmethod
    def aggressive(cls, *, i_accept_the_risk: bool = False) -> RateLimitConfig:
        """Create a faster configuration. USE WITH CAUTION.

        Args:
            i_accept_the_risk: Must be True to acknowledge the risk of rate limiting.

        Returns:
            Configuration with faster settings.

        Raises:
            ValueError: If i_accept_the_risk is not True.
        """
        if not i_accept_the_risk:
            raise ValueError(
                "You must pass i_accept_the_risk=True to use aggressive settings.\n"
                "This acknowledges that you may be rate-limited or suspended by Gmail."
            )

        print(
            "\n🚨 AGGRESSIVE MODE ENABLED 🚨\n"
            "You have opted into faster sending settings.\n"
            "If you get rate-limited, wait 1-24 hours before retrying.\n",
            file=sys.stderr,
        )

        return cls(
            delay_seconds=5,
            batch_size=75,
            batch_delay_seconds=30,
            warn_on_unsafe=True,
        )


@dataclass
class BulkSendResult:
    """Result of a bulk send operation.

    Attributes:
        total: Total number of emails attempted.
        sent: Number of emails successfully sent.
        failed: Number of emails that failed.
        failures: List of (recipient, error_message) tuples for failed emails.
    """

    total: int = 0
    sent: int = 0
    failed: int = 0
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate success rate as a percentage."""
        if self.total == 0:
            return 0.0
        return (self.sent / self.total) * 100


class SMTPClient:
    """SMTP client for sending emails.

    Usage:
        # Simple - auto-detect credentials from Keychain/env
        client = SMTPClient(provider="gmail")
        client.send(
            to=["recipient@example.com"],
            subject="Hello",
            body="Message body",
        )

        # Explicit credentials
        client = SMTPClient(
            provider="gmail",
            user="sender@gmail.com",
            password="app-password",
        )

        # HTML email
        client.send(
            to=["recipient@example.com"],
            subject="Hello",
            body="<h1>HTML Message</h1>",
            html=True,
        )
    """

    def __init__(
        self,
        provider: str = "gmail",
        user: str | None = None,
        password: str | None = None,
        use_keychain: bool = True,
    ) -> None:
        """Initialize SMTP client.

        Args:
            provider: Provider name ("gmail").
            user: Email address for authentication.
            password: Password or app password.
            use_keychain: Whether to check macOS Keychain for credentials.

        Raises:
            ValueError: If provider is not supported.
        """
        if provider not in PROVIDERS:
            raise ValueError(f"Unknown provider: {provider}. Supported: {list(PROVIDERS.keys())}")

        provider_cls = PROVIDERS[provider]
        self._provider: BaseSMTPProvider = provider_cls(
            user=user,
            password=password,
            use_keychain=use_keychain,
        )

    @property
    def user(self) -> str:
        """Get the authenticated user email."""
        user, _ = self._provider.get_credentials()
        return user

    def send(
        self,
        to: list[str],
        subject: str,
        body: str,
        html: bool = False,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        from_name: str | None = None,
    ) -> None:
        """Send an email.

        Args:
            to: List of recipient email addresses.
            subject: Email subject line.
            body: Email body (plain text or HTML).
            html: If True, body is HTML; otherwise plain text.
            cc: List of CC recipients.
            bcc: List of BCC recipients.
            from_name: Display name for sender (e.g., "Professor Smith").

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Failed to connect to server.
            SMTPSendError: Failed to send email.
        """
        user, password = self._provider.get_credentials()

        # Build message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["To"] = ", ".join(to)

        if from_name:
            msg["From"] = f"{from_name} <{user}>"
        else:
            msg["From"] = user

        if cc:
            msg["Cc"] = ", ".join(cc)

        # Attach body
        content_type = "html" if html else "plain"
        msg.attach(MIMEText(body, content_type))

        # Calculate all recipients for SMTP
        all_recipients = list(to)
        if cc:
            all_recipients.extend(cc)
        if bcc:
            all_recipients.extend(bcc)

        # Send
        try:
            with smtplib.SMTP(self._provider.host, self._provider.port) as server:
                if self._provider.use_tls:
                    server.starttls()
                try:
                    server.login(user, password)
                except smtplib.SMTPAuthenticationError as e:
                    raise SMTPAuthError(f"Authentication failed: {e}") from e
                server.send_message(msg, to_addrs=all_recipients)
        except smtplib.SMTPConnectError as e:
            raise SMTPConnectionError(
                f"Failed to connect to {self._provider.host}:{self._provider.port}: {e}"
            ) from e
        except smtplib.SMTPException as e:
            if isinstance(e, smtplib.SMTPAuthenticationError):
                raise  # Already converted above
            raise SMTPSendError(f"Failed to send email: {e}") from e

    def test_connection(self) -> bool:
        """Test SMTP connection and authentication.

        Returns:
            True if connection and auth succeed.

        Raises:
            SMTPAuthError: Authentication failed.
            SMTPConnectionError: Failed to connect.
        """
        user, password = self._provider.get_credentials()

        try:
            with smtplib.SMTP(self._provider.host, self._provider.port) as server:
                if self._provider.use_tls:
                    server.starttls()
                try:
                    server.login(user, password)
                except smtplib.SMTPAuthenticationError as e:
                    raise SMTPAuthError(f"Authentication failed: {e}") from e
                return True
        except smtplib.SMTPConnectError as e:
            raise SMTPConnectionError(
                f"Failed to connect to {self._provider.host}:{self._provider.port}: {e}"
            ) from e

    def send_bulk(
        self,
        recipients: list[dict[str, str]],
        subject: str,
        body_template: str,
        html: bool = False,
        from_name: str | None = None,
        rate_limit: RateLimitConfig | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
        on_error: Callable[[str, str, Exception], None] | None = None,
    ) -> BulkSendResult:
        """Send personalized emails to multiple recipients with rate limiting.

        This method implements conservative rate limiting by default to prevent
        Gmail from suspending your account. Each recipient receives an individual
        email with optional personalization.

        Args:
            recipients: List of dicts with at minimum an 'email' key.
                Additional keys can be used for template substitution.
                Example: [{"email": "a@example.com", "name": "Alice"}, ...]
            subject: Email subject line (can include {placeholders}).
            body_template: Email body template with {placeholders} for personalization.
                Example: "Dear {name},\\n\\nYour message here."
            html: If True, body is HTML; otherwise plain text.
            from_name: Display name for sender (e.g., "Professor Smith").
            rate_limit: Rate limiting configuration. Uses conservative defaults if None.
            on_progress: Optional callback(sent_count, total_count, current_email)
                called after each successful send.
            on_error: Optional callback(email, error_type, exception) called on failures.

        Returns:
            BulkSendResult with counts of sent/failed emails and failure details.

        Example:
            >>> client = SMTPClient(provider="gmail")
            >>> recipients = [
            ...     {"email": "alice@example.com", "first_name": "Alice"},
            ...     {"email": "bob@example.com", "first_name": "Bob"},
            ... ]
            >>> result = client.send_bulk(
            ...     recipients=recipients,
            ...     subject="Class Update",
            ...     body_template="Dear {first_name},\\n\\nPlease watch the video.",
            ...     from_name="Professor Smith",
            ... )
            >>> print(f"Sent: {result.sent}/{result.total}")
        """
        if rate_limit is None:
            rate_limit = RateLimitConfig.conservative()

        result = BulkSendResult(total=len(recipients))

        # Warn about total count
        if len(recipients) > 100:
            estimated_time = (
                len(recipients) * rate_limit.delay_seconds
                + (len(recipients) // rate_limit.batch_size) * rate_limit.batch_delay_seconds
            )
            print(
                f"\n📧 Sending {len(recipients)} emails with {rate_limit.delay_seconds}s delay.\n"
                f"   Estimated time: {estimated_time / 60:.1f} minutes\n"
                f"   Batch size: {rate_limit.batch_size}, batch delay: {rate_limit.batch_delay_seconds}s\n",
                file=sys.stderr,
            )

        for i, recipient in enumerate(recipients):
            email = recipient.get("email")
            if not email:
                result.failed += 1
                result.failures.append(("unknown", "No 'email' key in recipient dict"))
                continue

            # Format subject and body with recipient data
            try:
                formatted_subject = subject.format(**recipient)
                formatted_body = body_template.format(**recipient)
            except KeyError as e:
                result.failed += 1
                error_msg = f"Missing template key: {e}"
                result.failures.append((email, error_msg))
                if on_error:
                    on_error(email, "template_error", e)
                continue

            # Send the email
            try:
                self.send(
                    to=[email],
                    subject=formatted_subject,
                    body=formatted_body,
                    html=html,
                    from_name=from_name,
                )
                result.sent += 1

                if on_progress:
                    on_progress(result.sent, result.total, email)

            except (SMTPAuthError, SMTPConnectionError, SMTPSendError) as e:
                result.failed += 1
                result.failures.append((email, str(e)))
                if on_error:
                    on_error(email, type(e).__name__, e)

                # If we get a connection error, it might be rate limiting
                if isinstance(e, SMTPConnectionError) or "Connection unexpectedly closed" in str(e):
                    print(
                        f"\n🚨 Connection error after {result.sent} emails.\n"
                        f"   This may indicate rate limiting. Consider waiting before retrying.\n",
                        file=sys.stderr,
                    )

            # Rate limiting delays
            if i < len(recipients) - 1:  # Don't delay after last email
                # Check if we're at a batch boundary
                if (i + 1) % rate_limit.batch_size == 0:
                    print(
                        f"\n⏸️  Batch of {rate_limit.batch_size} complete. "
                        f"Pausing {rate_limit.batch_delay_seconds}s...\n",
                        file=sys.stderr,
                    )
                    time.sleep(rate_limit.batch_delay_seconds)
                else:
                    time.sleep(rate_limit.delay_seconds)

        # Final summary
        print(
            f"\n{'=' * 60}\n"
            f"📊 BULK SEND COMPLETE\n"
            f"{'=' * 60}\n"
            f"   Total: {result.total}\n"
            f"   Sent:  {result.sent} ({result.success_rate:.1f}%)\n"
            f"   Failed: {result.failed}\n"
            f"{'=' * 60}\n",
            file=sys.stderr,
        )

        if result.failures:
            print(
                "\n❌ Failed recipients:\n"
                + "\n".join(f"   - {email}: {error}" for email, error in result.failures[:10]),
                file=sys.stderr,
            )
            if len(result.failures) > 10:
                print(f"   ... and {len(result.failures) - 10} more\n", file=sys.stderr)

        return result
