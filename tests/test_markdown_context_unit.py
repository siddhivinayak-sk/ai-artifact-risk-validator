"""Unit tests for MarkdownFenceTracker."""

from __future__ import annotations

from ai_artifact_risk_validator.scanners._markdown_context import (
    FenceRegion,
    MarkdownFenceTracker,
)


def test_basic_fence_detection() -> None:
    """Lines inside a fence are correctly identified."""
    lines = [
        "# Header",
        "```python",
        'print("hello")',
        "```",
        "Some prose",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert tracker.is_fence_boundary(2)
    assert tracker.is_in_fence(3)
    assert tracker.is_fence_boundary(4)
    assert not tracker.is_in_fence(1)
    assert not tracker.is_in_fence(5)


def test_unmatched_opener_extends_to_eof() -> None:
    """Unmatched fence opener extends to end of file."""
    lines = [
        "text",
        "```",
        "code line 1",
        "code line 2",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert tracker.is_fence_boundary(2)
    assert tracker.is_in_fence(3)
    assert tracker.is_in_fence(4)
    # No real closer, so only the opener is a boundary
    assert not tracker.is_fence_boundary(4)
    assert not tracker.is_in_fence(1)
    assert not tracker.is_in_fence(2)  # opener itself is not "in" fence


def test_consecutive_fences() -> None:
    """Consecutive fences are independently tracked."""
    lines = [
        "```",
        "block 1",
        "```",
        "```",
        "block 2",
        "```",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert tracker.is_fence_boundary(1)
    assert tracker.is_in_fence(2)
    assert tracker.is_fence_boundary(3)
    assert tracker.is_fence_boundary(4)
    assert tracker.is_in_fence(5)
    assert tracker.is_fence_boundary(6)
    assert not tracker.is_in_fence(1)
    assert not tracker.is_in_fence(3)


def test_nested_fences_higher_backtick_count() -> None:
    """Inner 3-backtick fences don't close a 4-backtick outer fence."""
    lines = [
        "````",
        "```",
        "inner content",
        "```",
        "````",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert tracker.is_fence_boundary(1)
    assert tracker.is_in_fence(2)
    assert tracker.is_in_fence(3)
    assert tracker.is_in_fence(4)
    assert tracker.is_fence_boundary(5)


def test_empty_input() -> None:
    """Empty input produces no fence regions."""
    tracker = MarkdownFenceTracker([])
    assert not tracker.is_in_fence(1)
    assert not tracker.is_fence_boundary(1)
    assert tracker.regions == []


def test_fence_region_dataclass() -> None:
    """FenceRegion dataclass fields are set correctly."""
    lines = [
        "```js",
        "console.log(42)",
        "```",
    ]
    tracker = MarkdownFenceTracker(lines)
    regions = tracker.regions
    assert len(regions) == 1
    assert regions[0].start_line == 1
    assert regions[0].end_line == 3
    assert regions[0].backtick_count == 3


def test_fence_with_indented_backticks() -> None:
    """Indented fence markers are recognized."""
    lines = [
        "  ```python",
        "  code here",
        "  ```",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert tracker.is_fence_boundary(1)
    assert tracker.is_in_fence(2)
    assert tracker.is_fence_boundary(3)


def test_fence_boundary_not_in_fence() -> None:
    """Fence boundary lines are not reported as 'in fence'."""
    lines = [
        "```",
        "inside",
        "```",
    ]
    tracker = MarkdownFenceTracker(lines)
    assert not tracker.is_in_fence(1)
    assert not tracker.is_in_fence(3)
    assert tracker.is_in_fence(2)


def test_multiple_regions() -> None:
    """Multiple fence regions are all tracked."""
    lines = [
        "text",
        "```",
        "a",
        "```",
        "text",
        "```",
        "b",
        "c",
        "```",
    ]
    tracker = MarkdownFenceTracker(lines)
    regions = tracker.regions
    assert len(regions) == 2
    assert regions[0] == FenceRegion(start_line=2, end_line=4, backtick_count=3)
    assert regions[1] == FenceRegion(start_line=6, end_line=9, backtick_count=3)


def test_closer_needs_same_or_more_backticks() -> None:
    """A closer with fewer backticks does not close a fence."""
    lines = [
        "````",
        "```",
        "still inside",
        "````",
    ]
    tracker = MarkdownFenceTracker(lines)
    # ``` (3 backticks) cannot close ```` (4 backticks)
    assert tracker.is_in_fence(2)
    assert tracker.is_in_fence(3)
    assert tracker.is_fence_boundary(4)


def test_closer_with_more_backticks_closes() -> None:
    """A closer with more backticks than the opener closes the fence."""
    lines = [
        "```",
        "content",
        "````",
    ]
    tracker = MarkdownFenceTracker(lines)
    # ```` (4 backticks) can close ``` (3 backticks)
    assert tracker.is_fence_boundary(1)
    assert tracker.is_in_fence(2)
    assert tracker.is_fence_boundary(3)
