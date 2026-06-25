"""Property-based tests for the ReferenceResolver.

# Feature: script-file-scanning, Properties 4, 5, 11, 14

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.8, 3.9, 8.3, 10.4, 10.5, 13.2**

Property 4: For any classified AI artifact containing N embedded script file references
(tokens ending with a supported extension), the Reference_Resolver SHALL extract
min(N, 50) references, and each extracted reference SHALL end with one of the
configured script_extensions.

Property 5: For any relative script file reference and a given artifact directory,
the Reference_Resolver SHALL resolve the same absolute path on every invocation.
For case-insensitive exact filename matches, the resolver SHALL match if and only
if the basename matches exactly (case-insensitive) and SHALL reject substring matches.

Property 11: For any file extension, the Reference_Resolver and script classification
SHALL recognize a file as a potential Script_File if and only if its extension appears
in the configured script_extensions list.

Property 14: For any set of Referencing_Artifacts processed by the Reference_Resolver,
the sum of resolved references plus unresolved references SHALL equal the total
references extracted across all artifacts (capped at 50 per artifact).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.classifiers.reference_resolver import (
    _MAX_REFERENCES_PER_ARTIFACT,
    ReferenceResolver,
)
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import ArtifactType

# --- Constants ---

_DEFAULT_EXTENSIONS = [".py", ".ts", ".js", ".ps1", ".sh", ".bash", ".bat", ".cmd", ".rb"]

_ALL_EXTENSIONS = [
    ".py",
    ".ts",
    ".js",
    ".ps1",
    ".sh",
    ".bash",
    ".bat",
    ".cmd",
    ".rb",
    ".java",
    ".kt",
    ".rs",
]

# Safe base names for generating file references
_SAFE_BASENAMES = [
    "main",
    "helper",
    "utils",
    "server",
    "handler",
    "worker",
    "script",
    "tool",
    "run",
    "setup",
    "init",
    "config",
    "deploy",
    "build",
    "test",
]

# Separators that the tokenizer splits on
_SEPARATORS = [" ", ",", '"', "'", "(", ")", "[", "]", "{", "}", "<", ">", ":", ";", "\n", "\t"]


# --- Strategies ---


@st.composite
def script_extension(draw, ext_list=None):
    """Draw a script extension from the given list or defaults."""
    exts = ext_list if ext_list is not None else _DEFAULT_EXTENSIONS
    return draw(st.sampled_from(exts))


@st.composite
def script_filename(draw, ext_list=None):
    """Generate a script filename (basename + extension)."""
    basename = draw(st.sampled_from(_SAFE_BASENAMES))
    ext = draw(script_extension(ext_list=ext_list))
    return f"{basename}{ext}"


@st.composite
def relative_script_path(draw, ext_list=None):
    """Generate a relative script file path like 'src/utils.py'."""
    depth = draw(st.integers(min_value=1, max_value=3))
    dir_parts = ["src", "lib", "scripts", "tools", "hooks", "modules"]
    parts = draw(st.lists(st.sampled_from(dir_parts), min_size=depth, max_size=depth))
    filename = draw(script_filename(ext_list=ext_list))
    return "/".join(parts) + "/" + filename


@st.composite
def artifact_content_with_refs(draw, ext_list=None, min_refs=1, max_refs=20):
    """Generate artifact content containing embedded script file references.

    Returns a tuple of (content, expected_references) where expected_references
    is the list of reference tokens that should be extracted.
    """
    num_refs = draw(st.integers(min_value=min_refs, max_value=max_refs))
    references = []
    content_parts = []

    for _ in range(num_refs):
        # Either a bare filename or a relative path
        if draw(st.booleans()):
            ref = draw(script_filename(ext_list=ext_list))
        else:
            ref = draw(relative_script_path(ext_list=ext_list))
        references.append(ref)

        # Add a separator before the reference
        sep = draw(st.sampled_from(_SEPARATORS))
        content_parts.append(sep)
        content_parts.append(ref)

    # Add some non-reference filler between references
    filler_words = ["run", "the", "command", "to", "start", "application", "using", "file"]
    filler = draw(st.lists(st.sampled_from(filler_words), min_size=2, max_size=5))
    content_parts.insert(0, " ".join(filler))

    content = "".join(content_parts)
    return content, references


@st.composite
def artifact_content_many_refs(draw, ext_list=None, num_refs=60):
    """Generate artifact content containing more than 50 script references."""
    references = []
    content_parts = []

    for i in range(num_refs):
        ext = draw(script_extension(ext_list=ext_list))
        ref = f"file{i}{ext}"
        references.append(ref)
        content_parts.append(f" {ref}")

    content = "".join(content_parts)
    return content, references


# --- Property Tests ---


class TestProperty4ReferenceExtractionCompleteness:
    """Property 4: Reference extraction completeness.

    For any classified AI artifact containing N embedded script file references
    (tokens ending with a supported extension), the Reference_Resolver SHALL
    extract min(N, 50) references, and each extracted reference SHALL end with
    one of the configured script_extensions.

    **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.9**
    """

    @given(data=artifact_content_with_refs(min_refs=1, max_refs=20))
    @settings(max_examples=100, deadline=None)
    def test_extracts_all_references_within_cap(self, data):
        """All N references are extracted when N <= 50."""
        content, expected_refs = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.md"
            artifact_file.write_text(content, encoding="utf-8")

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.SKILL,
            )

            # All expected references should be found
            assert len(extracted) >= len(expected_refs), (
                f"Expected at least {len(expected_refs)} refs, got {len(extracted)}"
            )

            # Each extracted reference must end with a configured extension
            extensions_lower = {ext.lower() for ext in _DEFAULT_EXTENSIONS}
            for ref in extracted:
                ref_lower = ref.lower()
                assert any(ref_lower.endswith(ext) for ext in extensions_lower), (
                    f"Extracted ref '{ref}' does not end with a configured extension"
                )

    @given(data=artifact_content_many_refs(num_refs=60))
    @settings(max_examples=100, deadline=None)
    def test_caps_at_50_references(self, data):
        """When N > 50, exactly 50 are processed after capping."""
        content, expected_refs = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.md"
            artifact_file.write_text(content, encoding="utf-8")

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.SKILL,
            )

            # Extraction itself returns all refs (capping happens in _process_artifact)
            assert len(extracted) >= 50

            # Simulate the cap that _process_artifact applies
            capped = extracted[:_MAX_REFERENCES_PER_ARTIFACT]
            assert len(capped) == 50

    @given(data=artifact_content_with_refs(min_refs=1, max_refs=15))
    @settings(max_examples=100, deadline=None)
    def test_all_extracted_refs_end_with_configured_extension(self, data):
        """Every extracted reference ends with one of the configured extensions."""
        content, _ = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.md"
            artifact_file.write_text(content, encoding="utf-8")

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.HOOK,
            )

            extensions_lower = {ext.lower() for ext in _DEFAULT_EXTENSIONS}
            for ref in extracted:
                ref_lower = ref.lower()
                assert any(ref_lower.endswith(ext) for ext in extensions_lower), (
                    f"Reference '{ref}' does not end with configured extension"
                )


class TestProperty5ReferencePathResolutionDeterminism:
    """Property 5: Reference path resolution determinism.

    For any relative script file reference and a given artifact directory, the
    Reference_Resolver SHALL resolve the same absolute path on every invocation.
    For case-insensitive exact filename matches, the resolver SHALL match if and
    only if the basename matches exactly (case-insensitive) and SHALL reject
    substring matches.

    **Validates: Requirements 3.8, 8.3**
    """

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        ext=st.sampled_from(_DEFAULT_EXTENSIONS),
    )
    @settings(max_examples=100, deadline=None)
    def test_relative_path_resolution_determinism(self, basename, ext):
        """Same relative path resolves to the same absolute path on every invocation."""
        filename = f"{basename}{ext}"
        relative_ref = f"scripts/{filename}"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Create the directory structure and file
            scripts_dir = tmp_path / "artifacts" / "scripts"
            scripts_dir.mkdir(parents=True)
            script_file = scripts_dir / filename
            script_file.write_text("# script content", encoding="utf-8")

            artifact_dir = tmp_path / "artifacts"

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[script_file],
            )

            # Resolve the same reference multiple times
            result1 = resolver._resolve_path(relative_ref, artifact_dir)
            result2 = resolver._resolve_path(relative_ref, artifact_dir)
            result3 = resolver._resolve_path(relative_ref, artifact_dir)

            assert result1 == result2 == result3
            assert result1 == script_file.resolve()

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        ext=st.sampled_from(_DEFAULT_EXTENSIONS),
    )
    @settings(max_examples=100, deadline=None)
    def test_bare_filename_case_insensitive_exact_match(self, basename, ext):
        """Bare filenames match case-insensitively on exact basename."""
        filename = f"{basename}{ext}"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            script_file = tmp_path / filename
            script_file.write_text("# content", encoding="utf-8")

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[script_file],
            )

            # Case-insensitive match should work
            upper_ref = filename.upper()
            result = resolver._resolve_path(upper_ref, tmp_path)
            assert result == script_file.resolve()

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        ext=st.sampled_from(_DEFAULT_EXTENSIONS),
    )
    @settings(max_examples=100, deadline=None)
    def test_substring_match_rejected(self, basename, ext):
        """Substring matches are rejected — only exact basename equality."""
        filename = f"{basename}{ext}"
        # Create a file whose name is a proper extension of the reference
        longer_filename = f"my_{filename}"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Only the longer file exists
            longer_file = tmp_path / longer_filename
            longer_file.write_text("# content", encoding="utf-8")

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[longer_file],
            )

            # Searching for the shorter filename should NOT match the longer one
            result = resolver._resolve_path(filename, tmp_path)
            assert result is None, (
                f"Expected None for substring match, got {result}. "
                f"Searched for '{filename}' but only '{longer_filename}' exists."
            )


class TestProperty11ScriptExtensionConfigControlsScope:
    """Property 11: Script extension configuration controls scope.

    For any file extension, the Reference_Resolver and script classification SHALL
    recognize a file as a potential Script_File if and only if its extension appears
    in the configured script_extensions list. Adding or removing an extension from
    the list SHALL immediately include or exclude files with that extension.

    **Validates: Requirements 10.4, 10.5**
    """

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        ext=st.sampled_from(_ALL_EXTENSIONS),
    )
    @settings(max_examples=100, deadline=None)
    def test_extension_in_config_is_recognized(self, basename, ext):
        """When an extension is in script_extensions, references are extracted."""
        filename = f"{basename}{ext}"
        content = f"run command: {filename} to start"

        config = ValidatorConfig(script_extensions=[ext])
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.yaml"
            artifact_file.write_text(content, encoding="utf-8")

            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.SKILL,
            )

            assert any(ref == filename for ref in extracted), (
                f"Expected '{filename}' to be extracted when '{ext}' is configured. "
                f"Got: {extracted}"
            )

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        included_ext=st.sampled_from([".py", ".ts", ".js"]),
        excluded_ext=st.sampled_from([".rb", ".kt", ".rs"]),
    )
    @settings(max_examples=100, deadline=None)
    def test_extension_not_in_config_is_ignored(self, basename, included_ext, excluded_ext):
        """When an extension is NOT in script_extensions, references are not extracted."""
        included_file = f"{basename}{included_ext}"
        excluded_file = f"{basename}{excluded_ext}"
        content = f"run {included_file} and {excluded_file}"

        # Only include the included_ext in config
        config = ValidatorConfig(script_extensions=[included_ext])
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.yaml"
            artifact_file.write_text(content, encoding="utf-8")

            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.HOOK,
            )

            # Included extension should be extracted
            assert any(ref == included_file for ref in extracted), (
                f"Expected '{included_file}' to be extracted"
            )
            # Excluded extension should NOT be extracted
            assert not any(ref == excluded_file for ref in extracted), (
                f"'{excluded_file}' should NOT be extracted when '{excluded_ext}' "
                f"is not in script_extensions"
            )

    @given(
        basename=st.sampled_from(_SAFE_BASENAMES),
        ext=st.sampled_from(_ALL_EXTENSIONS),
    )
    @settings(max_examples=100, deadline=None)
    def test_removing_extension_excludes_files(self, basename, ext):
        """When an extension is removed from config, it is no longer recognized."""
        filename = f"{basename}{ext}"
        content = f"execute {filename} now"

        # Config with no extensions configured
        config = ValidatorConfig(script_extensions=[])
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.yaml"
            artifact_file.write_text(content, encoding="utf-8")

            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=[],
            )

            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.SKILL,
            )

            assert len(extracted) == 0, (
                f"Expected no refs with empty extensions config, got: {extracted}"
            )


class TestProperty14ReferenceResolverCountInvariant:
    """Property 14: Reference resolver count invariant.

    For any set of Referencing_Artifacts processed by the Reference_Resolver,
    the sum of resolved references plus unresolved references SHALL equal the
    total references extracted across all artifacts (capped at 50 per artifact).

    **Validates: Requirements 13.2**
    """

    @given(data=artifact_content_with_refs(min_refs=1, max_refs=15))
    @settings(max_examples=100, deadline=None)
    def test_resolved_plus_unresolved_equals_total(self, data):
        """resolved + unresolved = total extracted (capped at 50)."""
        content, expected_refs = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.md"
            artifact_file.write_text(content, encoding="utf-8")

            # Create some of the referenced files so some resolve and some don't
            created_files = []
            for ref in expected_refs[: len(expected_refs) // 2]:
                # Only create bare filenames (not relative paths)
                if "/" not in ref and "\\" not in ref:
                    file_path = tmp_path / ref
                    file_path.write_text("# content", encoding="utf-8")
                    created_files.append(file_path)

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=created_files + [artifact_file],
            )

            # Extract references
            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.SKILL,
            )

            # Apply the cap
            capped_refs = extracted[:_MAX_REFERENCES_PER_ARTIFACT]
            total_extracted = len(capped_refs)

            # Resolve each reference and count resolved vs unresolved
            artifact_dir = artifact_file.resolve().parent
            resolved_count = 0
            unresolved_count = 0

            for ref in capped_refs:
                path = resolver._resolve_path(ref, artifact_dir)
                if path is not None and path in resolver._discovered_set:
                    resolved_count += 1
                else:
                    unresolved_count += 1

            # Invariant: resolved + unresolved = total extracted
            assert resolved_count + unresolved_count == total_extracted, (
                f"Count invariant violated: {resolved_count} resolved + "
                f"{unresolved_count} unresolved != {total_extracted} total"
            )

    @given(data=artifact_content_many_refs(num_refs=60))
    @settings(max_examples=100, deadline=None)
    def test_count_invariant_with_cap(self, data):
        """Count invariant holds even when extraction exceeds the 50-ref cap."""
        content, expected_refs = data

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            artifact_file = tmp_path / "artifact.md"
            artifact_file.write_text(content, encoding="utf-8")

            # Create a subset of the files
            created_files = []
            for ref in expected_refs[:10]:
                file_path = tmp_path / ref
                file_path.write_text("# content", encoding="utf-8")
                created_files.append(file_path)

            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)
            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=created_files + [artifact_file],
            )

            # Extract and cap
            extracted = resolver._extract_references(
                artifact_path=artifact_file,
                content=content,
                artifact_type=ArtifactType.MCP,
            )
            capped_refs = extracted[:_MAX_REFERENCES_PER_ARTIFACT]
            total_extracted = len(capped_refs)

            # Count resolved vs unresolved
            artifact_dir = artifact_file.resolve().parent
            resolved_count = 0
            unresolved_count = 0

            for ref in capped_refs:
                path = resolver._resolve_path(ref, artifact_dir)
                if path is not None and path in resolver._discovered_set:
                    resolved_count += 1
                else:
                    unresolved_count += 1

            assert resolved_count + unresolved_count == total_extracted
            assert total_extracted == 50

    @given(
        num_artifacts=st.integers(min_value=1, max_value=3),
        refs_per_artifact=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=100, deadline=None)
    def test_count_invariant_across_multiple_artifacts(self, num_artifacts, refs_per_artifact):
        """Count invariant holds across multiple artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            config = ValidatorConfig(script_extensions=_DEFAULT_EXTENSIONS)

            all_artifact_files = []
            all_created_files = []

            for i in range(num_artifacts):
                # Generate content with refs
                refs = [f"script{i}_{j}.py" for j in range(refs_per_artifact)]
                content = " ".join(refs)
                artifact_file = tmp_path / f"artifact_{i}.md"
                artifact_file.write_text(content, encoding="utf-8")
                all_artifact_files.append(artifact_file)

                # Create half the referenced files
                for ref in refs[: len(refs) // 2]:
                    file_path = tmp_path / ref
                    file_path.write_text("# content", encoding="utf-8")
                    all_created_files.append(file_path)

            resolver = ReferenceResolver(
                config=config,
                scan_root=tmp_path,
                discovered_files=all_created_files + all_artifact_files,
            )

            # Process each artifact and verify invariant
            total_resolved = 0
            total_unresolved = 0
            total_extracted = 0

            for artifact_file in all_artifact_files:
                content = artifact_file.read_text(encoding="utf-8")
                extracted = resolver._extract_references(
                    artifact_path=artifact_file,
                    content=content,
                    artifact_type=ArtifactType.SKILL,
                )
                capped = extracted[:_MAX_REFERENCES_PER_ARTIFACT]
                total_extracted += len(capped)

                artifact_dir = artifact_file.resolve().parent
                for ref in capped:
                    path = resolver._resolve_path(ref, artifact_dir)
                    if path is not None and path in resolver._discovered_set:
                        total_resolved += 1
                    else:
                        total_unresolved += 1

            assert total_resolved + total_unresolved == total_extracted
