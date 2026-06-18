"""Token budget tracker for LLM meta-analyzer calls.

Tracks tokens consumed per scan session to prevent runaway API costs.
The default budget is 10,000 tokens per scan; configurable via config.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Default maximum tokens per scan session
_DEFAULT_BUDGET: int = 10_000

# Approximate tokens-per-character ratio for budget estimation
_CHARS_PER_TOKEN: float = 4.0


class TokenBudget:
    """Tracks token consumption for LLM API calls within a scan session.

    Args:
        max_tokens: Maximum tokens allowed before LLM calls are skipped.
    """

    def __init__(self, max_tokens: int = _DEFAULT_BUDGET) -> None:
        self._max_tokens = max_tokens
        self._consumed: int = 0

    @property
    def remaining(self) -> int:
        """Remaining token budget."""
        return max(0, self._max_tokens - self._consumed)

    @property
    def is_exhausted(self) -> bool:
        """True if the token budget is exhausted."""
        return self._consumed >= self._max_tokens

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        return max(1, int(len(text) / _CHARS_PER_TOKEN))

    def can_afford(self, text: str) -> bool:
        """Check if the estimated token cost fits within the remaining budget."""
        return self.estimate_tokens(text) <= self.remaining

    def record_usage(self, tokens_used: int) -> None:
        """Record actual token usage from an API response.

        Args:
            tokens_used: Number of tokens consumed by the LLM call.
        """
        self._consumed += tokens_used
        logger.debug(
            "TokenBudget: consumed %d tokens (total: %d / %d)",
            tokens_used,
            self._consumed,
            self._max_tokens,
        )
        if self.is_exhausted:
            logger.info("TokenBudget: token budget exhausted (%d tokens)", self._max_tokens)

    def reset(self) -> None:
        """Reset budget consumption for a new scan session."""
        self._consumed = 0
