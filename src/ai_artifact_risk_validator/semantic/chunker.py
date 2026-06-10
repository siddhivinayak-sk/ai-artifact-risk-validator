"""Smart text chunking for embedding-based analysis.

Splits text into semantically meaningful chunks respecting sentence
boundaries, YAML/JSON block structure, and Markdown sections.  This
ensures embedding quality by keeping related content together rather
than chopping mid-sentence.
"""

from __future__ import annotations

import re

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")
_YAML_BLOCK = re.compile(r"^---\s*$", re.MULTILINE)
_MARKDOWN_HEADING = re.compile(r"^#{1,6}\s", re.MULTILINE)
_JSON_ARRAY_ITEM = re.compile(r"^\s*\{", re.MULTILINE)

# Default max tokens approximation (1 token ≈ 4 chars for English)
_CHARS_PER_TOKEN = 4
_DEFAULT_MAX_TOKENS = 128


def chunk_text(
    text: str,
    *,
    max_tokens: int = _DEFAULT_MAX_TOKENS,
    overlap_tokens: int = 16,
) -> list[str]:
    """Split *text* into chunks of roughly *max_tokens* tokens.

    The function first tries structural boundaries (YAML ``---``,
    Markdown headings, JSON array items) and falls back to sentence
    boundaries.  Each chunk is at most *max_tokens* tokens and adjacent
    chunks share *overlap_tokens* tokens of trailing context from the
    previous chunk.

    Args:
        text: Source text to chunk.
        max_tokens: Maximum tokens per chunk (approximate).
        overlap_tokens: Overlap tokens between consecutive chunks.

    Returns:
        List of non-empty text chunks.
    """
    if not text or not text.strip():
        return []

    max_chars = max_tokens * _CHARS_PER_TOKEN
    overlap_chars = min(overlap_tokens * _CHARS_PER_TOKEN, max_chars // 4)

    # 1. Try structural split first
    segments = _split_structural(text)

    # 2. If no structural split produced >1 segment, use sentence split
    if len(segments) <= 1:
        segments = _split_sentences(text)

    # 3. Merge small segments and break large ones
    chunks = _merge_and_break(segments, max_chars, overlap_chars)
    return [c.strip() for c in chunks if c.strip()]


def _split_structural(text: str) -> list[str]:
    """Split on YAML front-matter, Markdown headings, or JSON blocks."""
    # YAML document separators
    parts = _YAML_BLOCK.split(text)
    if len(parts) > 1:
        return [p for p in parts if p.strip()]

    # Markdown headings
    positions = [m.start() for m in _MARKDOWN_HEADING.finditer(text)]
    if len(positions) > 1:
        segments: list[str] = []
        for i, pos in enumerate(positions):
            end = positions[i + 1] if i + 1 < len(positions) else len(text)
            segments.append(text[pos:end])
        # Include any preamble before the first heading
        if positions[0] > 0:
            preamble = text[: positions[0]].strip()
            if preamble:
                segments.insert(0, preamble)
        return segments

    return [text]


def _split_sentences(text: str) -> list[str]:
    """Split text on sentence boundaries."""
    parts = _SENTENCE_END.split(text)
    return [p for p in parts if p.strip()]


def _merge_and_break(
    segments: list[str],
    max_chars: int,
    overlap_chars: int,
) -> list[str]:
    """Merge small segments and break oversized ones with overlap."""
    chunks: list[str] = []
    current = ""

    for seg in segments:
        if len(current) + len(seg) + 1 <= max_chars:
            current = f"{current} {seg}".strip() if current else seg
        else:
            if current:
                chunks.append(current)
            # If the segment itself exceeds max_chars, break it
            if len(seg) > max_chars:
                sub_chunks = _hard_break(seg, max_chars, overlap_chars)
                chunks.extend(sub_chunks)
                current = ""
            else:
                # Start new chunk with overlap from previous
                if chunks and overlap_chars > 0:
                    prev_tail = chunks[-1][-overlap_chars:]
                    current = f"{prev_tail} {seg}".strip()
                else:
                    current = seg

    if current:
        chunks.append(current)

    return chunks


def _hard_break(text: str, max_chars: int, overlap_chars: int) -> list[str]:
    """Break a long text on word boundaries with overlap."""
    words = text.split()
    chunks: list[str] = []
    current = ""

    for word in words:
        candidate = f"{current} {word}".strip() if current else word
        if len(candidate) <= max_chars:
            current = candidate
        else:
            if current:
                chunks.append(current)
            # Overlap from previous chunk
            if chunks and overlap_chars > 0:
                prev_tail = chunks[-1][-overlap_chars:]
                current = f"{prev_tail} {word}".strip()
            else:
                current = word

    if current:
        chunks.append(current)

    return chunks
