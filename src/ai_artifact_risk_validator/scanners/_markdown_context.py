"""Markdown context utilities for scanner false positive reduction.

Provides lightweight stateful parsing of Markdown code fence boundaries,
enabling scanners to distinguish code blocks from prose content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)

# Regex matching a Markdown code fence line: 3+ backticks, optional language id
_FENCE_PATTERN = re.compile(r"^(\s*(`{3,}))(.*)?$")


@dataclass
class FenceRegion:
    """Represents a Markdown code fence region."""

    start_line: int  # 1-based, the opener line
    end_line: int  # 1-based, the closer line
    backtick_count: int  # Number of backticks in the opener


class MarkdownFenceTracker:
    """Tracks whether a given line is inside a Markdown code fence.

    Pre-computes fence ranges in __init__ for O(1) lookup per line.
    Handles nested/consecutive fences by matching fence markers with
    same or greater backtick count. Unmatched openers extend to end-of-file.
    """

    def __init__(self, lines: list[str]) -> None:
        """Parse lines and pre-compute fence regions.

        Args:
            lines: The content lines (0-indexed list, but line numbers are 1-based).
        """
        self._regions: list[FenceRegion] = []
        self._fence_lines: set[int] = set()  # 1-based line numbers on boundaries
        self._inside_fence: set[int] = set()  # 1-based line numbers inside fences
        self._compute_regions(lines)

    def _compute_regions(self, lines: list[str]) -> None:
        """Walk through lines and identify fence regions."""
        total_lines = len(lines)
        i = 0

        while i < total_lines:
            line = lines[i]
            match = _FENCE_PATTERN.match(line)

            if match:
                backtick_count = len(match.group(2))
                opener_line = i + 1  # Convert to 1-based

                # Search for a matching closer: same or greater backtick count,
                # with only whitespace (no language identifier content after backticks)
                closer_line = self._find_closer(lines, i + 1, backtick_count)

                if closer_line is None:
                    # Unmatched opener: extend to end-of-file
                    # All lines after the opener are inside the fence
                    end_line = total_lines  # 1-based, last line
                    region = FenceRegion(
                        start_line=opener_line,
                        end_line=end_line,
                        backtick_count=backtick_count,
                    )
                    self._regions.append(region)

                    # Only the opener is a boundary (no real closer)
                    self._fence_lines.add(opener_line)

                    # All lines after opener through EOF are inside
                    for line_num in range(opener_line + 1, end_line + 1):
                        self._inside_fence.add(line_num)

                    # Done — no more lines to process
                    break
                else:
                    region = FenceRegion(
                        start_line=opener_line,
                        end_line=closer_line,
                        backtick_count=backtick_count,
                    )
                    self._regions.append(region)

                    # Mark fence boundaries
                    self._fence_lines.add(opener_line)
                    self._fence_lines.add(closer_line)

                    # Mark interior lines as inside fence
                    for line_num in range(opener_line + 1, closer_line):
                        self._inside_fence.add(line_num)

                    # Skip past the closer line
                    i = closer_line  # 0-based index of next line after closer
            else:
                i += 1

    def _find_closer(
        self, lines: list[str], start_index: int, min_backtick_count: int
    ) -> int | None:
        """Find the closing fence line for an opener.

        Args:
            lines: All content lines.
            start_index: 0-based index to start searching from (line after opener).
            min_backtick_count: Minimum backtick count for a valid closer.

        Returns:
            1-based line number of the closer, or None if unmatched.
        """
        for j in range(start_index, len(lines)):
            match = _FENCE_PATTERN.match(lines[j])
            if match:
                closer_backticks = len(match.group(2))
                # A closer must have at least the same number of backticks
                # and should not have a language identifier (only whitespace after)
                remaining = match.group(3) or ""
                if closer_backticks >= min_backtick_count and remaining.strip() == "":
                    return j + 1  # Convert to 1-based
        return None

    def is_in_fence(self, line_num: int) -> bool:
        """Return True if line_num (1-based) is inside a code fence.

        This returns True for lines that are between a fence opener and closer,
        but NOT for the boundary lines themselves.

        Args:
            line_num: 1-based line number to check.

        Returns:
            True if the line is inside (between boundaries of) a code fence.
        """
        return line_num in self._inside_fence

    def is_fence_boundary(self, line_num: int) -> bool:
        """Return True if line_num (1-based) is a fence opener or closer.

        Args:
            line_num: 1-based line number to check.

        Returns:
            True if the line is a fence boundary (opener or closer).
        """
        return line_num in self._fence_lines

    @property
    def regions(self) -> list[FenceRegion]:
        """Return the list of detected fence regions (read-only access)."""
        return list(self._regions)
