"""Tests for the semantic text chunker."""

from __future__ import annotations

from ai_artifact_risk_validator.semantic.chunker import (
    _CHARS_PER_TOKEN,
    chunk_text,
)


class TestChunkTextBasics:
    """Basic chunking behaviour."""

    def test_empty_text_returns_empty(self) -> None:
        assert chunk_text("") == []

    def test_whitespace_only_returns_empty(self) -> None:
        assert chunk_text("   \n  ") == []

    def test_short_text_returns_single_chunk(self) -> None:
        result = chunk_text("Hello world.", max_tokens=64)
        assert result == ["Hello world."]

    def test_respects_max_tokens(self) -> None:
        text = "Word " * 200
        chunks = chunk_text(text.strip(), max_tokens=32)
        max_chars = 32 * _CHARS_PER_TOKEN
        for chunk in chunks:
            # Allow some slack for overlap
            assert len(chunk) <= max_chars + 100


class TestSentenceSplit:
    """Sentence-boundary splitting."""

    def test_splits_on_period(self) -> None:
        text = "First sentence. Second sentence. Third sentence."
        chunks = chunk_text(text, max_tokens=4)
        assert len(chunks) >= 2

    def test_splits_on_exclamation(self) -> None:
        text = "Alert! Something happened. OK."
        chunks = chunk_text(text, max_tokens=3)
        assert len(chunks) >= 2


class TestStructuralSplit:
    """Structural boundary splitting (YAML, Markdown)."""

    def test_yaml_front_matter(self) -> None:
        text = "title: Foo\n---\nbody content\n---\nmore"
        chunks = chunk_text(text, max_tokens=4)
        assert len(chunks) >= 2

    def test_markdown_headings(self) -> None:
        text = "# Heading 1\nParagraph one.\n## Heading 2\nParagraph two."
        chunks = chunk_text(text, max_tokens=8)
        assert len(chunks) >= 2

    def test_markdown_with_preamble(self) -> None:
        text = "Preamble text here.\n# Heading 1\nBody."
        chunks = chunk_text(text, max_tokens=128)
        assert any("Preamble" in c for c in chunks)


class TestOverlap:
    """Overlap between chunks."""

    def test_overlap_shares_context(self) -> None:
        # Create text where overlap should appear
        text = "A " * 100 + "MARKER. " + "B " * 100
        chunks = chunk_text(text.strip(), max_tokens=32, overlap_tokens=8)
        assert len(chunks) >= 2


class TestHardBreak:
    """Hard-break of very long segments."""

    def test_single_long_segment(self) -> None:
        text = "x " * 500
        chunks = chunk_text(text.strip(), max_tokens=32)
        assert len(chunks) > 1
        for chunk in chunks:
            assert len(chunk) > 0
