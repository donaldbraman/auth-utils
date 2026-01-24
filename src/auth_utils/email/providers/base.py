"""Base SMTP provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseSMTPProvider(ABC):
    """Abstract base class for SMTP providers."""

    @property
    @abstractmethod
    def host(self) -> str:
        """SMTP server hostname."""

    @property
    @abstractmethod
    def port(self) -> int:
        """SMTP server port."""

    @property
    @abstractmethod
    def use_tls(self) -> bool:
        """Whether to use STARTTLS."""

    @abstractmethod
    def get_credentials(self) -> tuple[str, str]:
        """Get (user, password) credentials.

        Raises:
            SMTPAuthError: If credentials cannot be obtained.
        """
