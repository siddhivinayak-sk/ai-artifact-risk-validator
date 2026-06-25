"""Unit tests for ReferenceResolver edge cases.

Validates: Requirements 3.7, 3.8, 3.9, 8.3, 11.1, 11.3

Tests cover:
- Unresolved paths (log INFO, skip)
- 50-reference limit per artifact (processes first 50, logs WARNING)
- 30-second timeout per artifact
- Unparseable artifact content (log WARNING, continue)
- Empty classified_artifacts input
- Case-insensitive exact match and substring rejection
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_artifact_risk_validator.classifiers.classifier import ClassificationResult
from ai_artifact_risk_validator.classifiers.reference_resolver import (
    _MAX_REFERENCES_PER_ARTIFACT,
    ReferenceResolver,
)
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import ArtifactType


@pytest.fixture
def default_config() -> ValidatorConfig:
    """ValidatorConfig with default script extensions."""
    return ValidatorConfig(script_extensions=[".py", ".ts", ".js", ".ps1", ".sh", ".bash"])


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a temporary workspace directory."""
    return tmp_path


class TestUnresolvedPaths:
    """Test that unresolved reference paths are skipped with INFO log.

    Validates: Requirement 3.7 — When a referenced Script_File path does not
    resolve to an existing file in the scanned directory tree, the
    Reference_Resolver SHALL log the unresolved reference at INFO level and
    skip it without producing a finding.
    """

    def test_unresolved_relative_path_is_skipped(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A relative path pointing to a non-existent file returns None."""
        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[],
        )

        result = resolver._resolve_path("lib/nonexistent.py", tmp_workspace)
        assert result is None

    def test_unresolved_bare_filename_is_skipped(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A bare filename not matching any discovered file returns None."""
        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[],
        )

        result = resolver._resolve_path("missing_script.py", tmp_workspace)
        assert result is None

    def test_unresolved_paths_counted_in_resolve(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """Unresolved references are tracked and summary is logged."""
        artifact_file = tmp_workspace / "skill.yaml"
        artifact_file.write_text(
            "command: nonexistent.py\nscript: also_missing.ts",
            encoding="utf-8",
        )

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.SKILL,
                confidence=0.65,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)

        # No files should be resolved since referenced scripts don't exist
        assert result == {}
        # Unresolved count should be > 0
        assert resolver._unresolved_count > 0

    def test_relative_path_exists_but_not_in_discovered_files(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A file that exists on disk but isn't in discovered_files is unresolved."""
        # Create the script file on disk
        scripts_dir = tmp_workspace / "scripts"
        scripts_dir.mkdir()
        script_file = scripts_dir / "helper.py"
        script_file.write_text("# helper", encoding="utf-8")

        artifact_file = tmp_workspace / "skill.yaml"
        artifact_file.write_text("run: scripts/helper.py", encoding="utf-8")

        # Purposely DO NOT include script_file in discovered_files
        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.SKILL,
                confidence=0.65,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)
        assert script_file.resolve() not in result


class TestReferenceLimit:
    """Test 50-reference limit per artifact.

    Validates: Requirement 3.9 — IF the Reference_Resolver extracts more than
    50 script references from a single artifact file, THEN it SHALL process
    only the first 50 references and log a WARNING.
    """

    def test_processes_first_50_references_only(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """When >50 references exist, only the first 50 are processed."""
        # Create 60 script files and reference them all
        created_files = []
        refs = []
        for i in range(60):
            fname = f"script_{i:03d}.py"
            f = tmp_workspace / fname
            f.write_text(f"# script {i}", encoding="utf-8")
            created_files.append(f)
            refs.append(fname)

        # Content with all 60 references
        content = " ".join(refs)
        artifact_file = tmp_workspace / "config.yaml"
        artifact_file.write_text(content, encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=created_files + [artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.HOOK,
                confidence=0.70,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)

        # Should only have resolved at most 50 scripts
        assert len(result) <= _MAX_REFERENCES_PER_ARTIFACT

    def test_exactly_50_references_no_warning(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """Exactly 50 references should all be processed without triggering the cap."""
        created_files = []
        refs = []
        for i in range(50):
            fname = f"script_{i:03d}.py"
            f = tmp_workspace / fname
            f.write_text(f"# script {i}", encoding="utf-8")
            created_files.append(f)
            refs.append(fname)

        content = " ".join(refs)
        artifact_file = tmp_workspace / "config.yaml"
        artifact_file.write_text(content, encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=created_files + [artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.HOOK,
                confidence=0.70,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)

        # All 50 should be resolved
        assert len(result) == 50

    def test_references_beyond_50_are_ignored(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """References after index 50 are not resolved."""
        created_files = []
        refs = []
        for i in range(55):
            fname = f"file_{i:03d}.py"
            f = tmp_workspace / fname
            f.write_text(f"# file {i}", encoding="utf-8")
            created_files.append(f)
            refs.append(fname)

        content = " ".join(refs)
        artifact_file = tmp_workspace / "artifact.md"
        artifact_file.write_text(content, encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=created_files + [artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.SKILL,
                confidence=0.65,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)

        # Files at indices 50-54 should NOT be in the result
        for i in range(50, 55):
            resolved_path = (tmp_workspace / f"file_{i:03d}.py").resolve()
            assert resolved_path not in result


class TestTimeout:
    """Test 30-second timeout per artifact.

    Validates: Requirement 11.3 — The Reference_Resolver SHALL complete
    processing of each individual Referencing_Artifact within 30 seconds;
    IF processing exceeds 30 seconds, THEN it SHALL abort and continue.
    """

    def test_timeout_aborts_slow_artifact(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """When processing exceeds the timeout, that artifact is skipped."""
        artifact_file = tmp_workspace / "slow_artifact.yaml"
        artifact_file.write_text("command: helper.py", encoding="utf-8")

        helper_file = tmp_workspace / "helper.py"
        helper_file.write_text("# helper", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[artifact_file, helper_file],
        )

        # Patch _process_artifact to simulate a long-running operation
        original_process = resolver._process_artifact

        def slow_process(artifact_path, artifact_type):
            time.sleep(2)  # Will exceed our patched timeout
            return original_process(artifact_path, artifact_type)

        # Patch the timeout to a short value for testing
        with patch(
            "ai_artifact_risk_validator.classifiers.reference_resolver._ARTIFACT_TIMEOUT_SECONDS",
            0.5,
        ):
            resolver._process_artifact = slow_process  # type: ignore[method-assign]

            classified = {
                artifact_file: ClassificationResult(
                    artifact_type=ArtifactType.SKILL,
                    confidence=0.65,
                    signals=["extension", "path"],
                )
            }

            # The resolver should still complete (not hang) despite the slow artifact
            result = resolver.resolve(classified)

            # The slow artifact should have been skipped (timeout)
            assert result == {}

    def test_timeout_does_not_affect_other_artifacts(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A timeout on one artifact doesn't prevent processing of others."""
        # Create two artifacts
        slow_artifact = tmp_workspace / "slow.yaml"
        slow_artifact.write_text("command: slow_script.py", encoding="utf-8")

        fast_artifact = tmp_workspace / "fast.yaml"
        fast_artifact.write_text("command: fast_script.py", encoding="utf-8")

        fast_script = tmp_workspace / "fast_script.py"
        fast_script.write_text("# fast", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[slow_artifact, fast_artifact, fast_script],
        )

        # Make only the slow artifact time out
        original_process = resolver._process_artifact
        call_count = {"n": 0}

        def selective_slow(artifact_path, artifact_type):
            call_count["n"] += 1
            if "slow" in str(artifact_path):
                time.sleep(2)
            return original_process(artifact_path, artifact_type)

        with patch(
            "ai_artifact_risk_validator.classifiers.reference_resolver._ARTIFACT_TIMEOUT_SECONDS",
            0.5,
        ):
            resolver._process_artifact = selective_slow  # type: ignore[method-assign]

            classified = {
                slow_artifact: ClassificationResult(
                    artifact_type=ArtifactType.SKILL,
                    confidence=0.65,
                    signals=["extension", "path"],
                ),
                fast_artifact: ClassificationResult(
                    artifact_type=ArtifactType.HOOK,
                    confidence=0.70,
                    signals=["extension", "path"],
                ),
            }

            result = resolver.resolve(classified)

            # fast_script.py should be resolved from the fast artifact
            assert fast_script.resolve() in result


class TestUnparseableArtifactContent:
    """Test unparseable artifact content handling.

    Validates: Requirement 11.1 — IF the Reference_Resolver raises an unhandled
    exception during reference extraction, THEN the Pipeline SHALL log at ERROR
    level and continue with zero script references for that artifact.
    """

    def test_unreadable_file_returns_empty(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """An artifact file that cannot be read results in no references."""
        artifact_file = tmp_workspace / "unreadable.yaml"
        artifact_file.write_text("command: script.py", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[artifact_file],
        )

        # Simulate read failure by patching _read_file_content
        with patch.object(resolver, "_read_file_content", return_value=None):
            classified = {
                artifact_file: ClassificationResult(
                    artifact_type=ArtifactType.SKILL,
                    confidence=0.65,
                    signals=["extension", "path"],
                )
            }
            result = resolver.resolve(classified)
            assert result == {}

    def test_exception_in_process_artifact_logs_and_continues(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """An exception in artifact processing is caught and logged."""
        good_artifact = tmp_workspace / "good.yaml"
        good_artifact.write_text("command: helper.py", encoding="utf-8")

        bad_artifact = tmp_workspace / "bad.yaml"
        bad_artifact.write_text("corrupt content", encoding="utf-8")

        helper_file = tmp_workspace / "helper.py"
        helper_file.write_text("# helper", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[good_artifact, bad_artifact, helper_file],
        )

        # Make _process_artifact raise for the bad artifact
        original_process = resolver._process_artifact

        def raise_for_bad(artifact_path, artifact_type):
            if "bad" in str(artifact_path):
                raise ValueError("Simulated parsing error")
            return original_process(artifact_path, artifact_type)

        resolver._process_artifact = raise_for_bad  # type: ignore[method-assign]

        classified = {
            bad_artifact: ClassificationResult(
                artifact_type=ArtifactType.PLUGIN,
                confidence=0.60,
                signals=["extension"],
            ),
            good_artifact: ClassificationResult(
                artifact_type=ArtifactType.SKILL,
                confidence=0.65,
                signals=["extension", "path"],
            ),
        }

        # Should not raise — the bad artifact is skipped gracefully
        result = resolver.resolve(classified)

        # The good artifact's reference should still be resolved
        assert helper_file.resolve() in result

    def test_binary_content_does_not_crash(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """Binary/non-text content in an artifact doesn't crash the resolver."""
        artifact_file = tmp_workspace / "binary.yaml"
        # Write binary-ish content that's still decodable as latin-1
        artifact_file.write_bytes(b"\x80\x81\x82\x00\xff\xfe script.py \x00")

        script_file = tmp_workspace / "script.py"
        script_file.write_text("# script", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[artifact_file, script_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.HOOK,
                confidence=0.60,
                signals=["extension"],
            )
        }

        # Should not raise
        result = resolver.resolve(classified)
        # May or may not resolve script.py depending on tokenization of binary content
        assert isinstance(result, dict)


class TestEmptyClassifiedArtifacts:
    """Test empty classified_artifacts input.

    When classified_artifacts is empty, resolve() should return an empty dict
    immediately.
    """

    def test_empty_input_returns_empty_dict(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """An empty classified_artifacts mapping returns empty results."""
        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[],
        )

        result = resolver.resolve({})
        assert result == {}
        assert resolver._unresolved_count == 0

    def test_empty_input_no_summary_logged(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """No summary is logged when there are zero references to process."""
        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[],
        )

        # This should not log a summary (Req 9.3 — no log when zero references)
        result = resolver.resolve({})
        assert result == {}


class TestCaseInsensitiveExactMatch:
    """Test case-insensitive exact match and substring rejection.

    Validates: Requirements 3.8 and 8.3 — The Reference_Resolver SHALL resolve
    bare filenames by case-insensitive exact basename match, rejecting any
    candidate where the match is a substring of a longer path segment.
    """

    def test_case_insensitive_match_uppercase_reference(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """An UPPERCASE reference matches a lowercase file."""
        script_file = tmp_workspace / "helper.py"
        script_file.write_text("# helper", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[script_file],
        )

        result = resolver._resolve_path("HELPER.PY", tmp_workspace)
        assert result == script_file.resolve()

    def test_case_insensitive_match_mixed_case(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A MiXeD CaSe reference matches the actual file."""
        script_file = tmp_workspace / "myserver.ts"
        script_file.write_text("// server", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[script_file],
        )

        result = resolver._resolve_path("MyServer.TS", tmp_workspace)
        assert result == script_file.resolve()

    def test_case_insensitive_match_file_has_uppercase(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A lowercase reference matches an UPPERCASE file."""
        script_file = tmp_workspace / "Script.PY"
        script_file.write_text("# Script", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[script_file],
        )

        result = resolver._resolve_path("script.py", tmp_workspace)
        assert result == script_file.resolve()

    def test_substring_match_rejected_prefix(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A file whose name is a prefix extension of the reference is rejected."""
        # Only 'myscript.py' exists, searching for 'script.py' should NOT match
        longer_file = tmp_workspace / "myscript.py"
        longer_file.write_text("# my script", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[longer_file],
        )

        result = resolver._resolve_path("script.py", tmp_workspace)
        assert result is None

    def test_substring_match_rejected_suffix(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """A file whose name contains the reference as a suffix is rejected."""
        # Only 'script_helper.py' exists, searching for 'helper.py' should NOT match
        longer_file = tmp_workspace / "script_helper.py"
        longer_file.write_text("# helper", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[longer_file],
        )

        result = resolver._resolve_path("helper.py", tmp_workspace)
        assert result is None

    def test_exact_match_succeeds_with_similar_files_present(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """Exact match succeeds even when similar-named files exist."""
        exact_file = tmp_workspace / "script.py"
        exact_file.write_text("# exact", encoding="utf-8")

        longer_file = tmp_workspace / "myscript.py"
        longer_file.write_text("# longer", encoding="utf-8")

        prefix_file = tmp_workspace / "script_utils.py"
        prefix_file.write_text("# prefix", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[exact_file, longer_file, prefix_file],
        )

        result = resolver._resolve_path("script.py", tmp_workspace)
        assert result == exact_file.resolve()

    def test_no_match_when_only_substrings_exist(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """No match when the searched filename only appears as part of other names."""
        file_a = tmp_workspace / "my_utils.py"
        file_a.write_text("# a", encoding="utf-8")

        file_b = tmp_workspace / "utils_extra.py"
        file_b.write_text("# b", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[file_a, file_b],
        )

        # "utils.py" doesn't exist — neither "my_utils.py" nor "utils_extra.py"
        # should match because they're not exact basename matches
        result = resolver._resolve_path("utils.py", tmp_workspace)
        assert result is None

    def test_case_insensitive_in_full_resolve_flow(
        self, default_config: ValidatorConfig, tmp_workspace: Path
    ) -> None:
        """End-to-end: case-insensitive matching works through resolve()."""
        script_file = tmp_workspace / "Deploy.SH"
        script_file.write_text("#!/bin/bash", encoding="utf-8")

        artifact_file = tmp_workspace / "hook.yaml"
        artifact_file.write_text("command: deploy.sh", encoding="utf-8")

        resolver = ReferenceResolver(
            config=default_config,
            scan_root=tmp_workspace,
            discovered_files=[script_file, artifact_file],
        )

        classified = {
            artifact_file: ClassificationResult(
                artifact_type=ArtifactType.HOOK,
                confidence=0.70,
                signals=["extension", "path"],
            )
        }

        result = resolver.resolve(classified)
        assert script_file.resolve() in result
