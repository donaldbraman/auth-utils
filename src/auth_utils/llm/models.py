"""
Data models for LLM client responses and messages.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

Provider = Literal["claude", "gemini", "chatgpt"]
Role = Literal["user", "assistant", "system"]


@dataclass
class Message:
    """A message in a conversation."""

    role: Role
    content: str


@dataclass
class UsageStats:
    """Token usage statistics from an LLM response."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        """Total tokens used."""
        return self.input_tokens + self.output_tokens


@dataclass
class LLMResponse:
    """Unified response from any LLM provider."""

    content: str
    model: str
    provider: Provider
    usage: UsageStats = field(default_factory=UsageStats)
    raw_response: Any = None

    def __str__(self) -> str:
        return self.content
