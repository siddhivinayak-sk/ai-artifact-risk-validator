"""Property-based test for ambiguous input confidence cap in RustAnalyzer.

**Validates: Requirements 2.9**

Property 21: Ambiguous Input Confidence Cap
Tests that when the RustAnalyzer detects a pattern but cannot determine whether
the input is user-controlled (data source is ambiguous), the confidence value
SHALL NOT exceed 0.70.

Ambiguous patterns include:
- SSRF detection (reqwest/hyper/surf) with a variable URL (not from format!)
- File system operations (std::fs) with a variable path
- Deserialization (serde_json/bincode/serde_yaml) with a variable input
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.rust_analyzer import RustAnalyzer

# --- Strategies ---

# Variable names that represent ambiguous input sources (not string literals,
# not format! macro — just plain variables whose origin is unclear)
_AMBIGUOUS_VAR_NAMES = st.sampled_from(
    [
        "url",
        "target_url",
        "endpoint",
        "addr",
        "uri",
        "path",
        "file_path",
        "input_path",
        "dir_path",
        "data",
        "input",
        "payload",
        "body",
        "content",
        "raw_input",
        "user_data",
        "request_body",
        "buf",
        "bytes",
        "msg",
    ]
)

# HTTP client libraries used in Rust
_HTTP_CLIENTS = st.sampled_from(["reqwest", "hyper", "surf"])

# HTTP methods
_HTTP_METHODS = st.sampled_from(["get", "post", "put", "delete", "patch"])

# File system operations (std::fs module functions)
_FS_OPERATIONS = st.sampled_from(
    [
        "read",
        "write",
        "read_to_string",
        "read_dir",
        "remove_file",
        "remove_dir",
        "create_dir",
        "copy",
        "rename",
        "metadata",
    ]
)

# Deserialization functions
_DESER_FUNCTIONS = st.sampled_from(
    [
        "serde_json::from_str",
        "serde_json::from_slice",
        "bincode::deserialize",
        "serde_yaml::from_str",
    ]
)

# Optional prefix code that adds context but does NOT add path validation
_AMBIENT_CODE_PREFIX = st.sampled_from(
    [
        "",
        "use std::io;\n",
        "fn main() {\n",
        "async fn handler(req: Request) -> Response {\n",
        "pub fn process(input: &str) -> Result<()> {\n",
        "#[tokio::main]\nasync fn main() {\n",
        "use serde::Deserialize;\n\n",
        "mod server {\n",
    ]
)

# Optional suffix code
_AMBIENT_CODE_SUFFIX = st.sampled_from(
    [
        "",
        "\n}",
        "\n    Ok(())\n}",
        '\n    println!("done");\n}',
    ]
)


@st.composite
def rust_ssrf_ambiguous_source(draw: st.DrawFn) -> str:
    """Generate Rust code with HTTP client usage where URL source is ambiguous.

    The URL is a plain variable (NOT constructed via format! macro),
    so the scanner cannot determine if it's user-controlled.
    """
    prefix = draw(_AMBIENT_CODE_PREFIX)
    suffix = draw(_AMBIENT_CODE_SUFFIX)
    client = draw(_HTTP_CLIENTS)
    method = draw(_HTTP_METHODS)
    var_name = draw(_AMBIGUOUS_VAR_NAMES)

    # Generate code patterns where URL comes from an ambiguous variable
    pattern = draw(
        st.sampled_from(
            [
                # Pattern: client.method(variable)
                f"    let response = {client}::Client::new().{method}({var_name}).send().await?;",
                # Pattern: reqwest::get(variable)
                f"    let response = {client}::get({var_name}).await?;",
                # Pattern: client instance method with variable
                f"    let client = {client}::Client::new();\n    let resp = client.{method}({var_name}).send().await?;",
            ]
        )
    )

    # Include use statement so scanner knows HTTP client is present
    use_stmt = f"use {client}::Client;\n"

    return f"{use_stmt}{prefix}    let {var_name} = get_url();\n{pattern}{suffix}"


@st.composite
def rust_fs_ambiguous_source(draw: st.DrawFn) -> str:
    """Generate Rust code with file system operations where path source is ambiguous.

    The path is a plain variable without preceding path validation
    (no canonicalize, starts_with, or strip_prefix).
    """
    prefix = draw(_AMBIENT_CODE_PREFIX)
    suffix = draw(_AMBIENT_CODE_SUFFIX)
    fs_op = draw(_FS_OPERATIONS)
    var_name = draw(_AMBIGUOUS_VAR_NAMES)

    # Generate fs operation with a variable path (no path validation nearby)
    pattern = draw(
        st.sampled_from(
            [
                f"    let result = std::fs::{fs_op}({var_name})?;",
                f"    let data = fs::{fs_op}({var_name})?;",
                f"    std::fs::{fs_op}({var_name})?;",
            ]
        )
    )

    use_stmt = "use std::fs;\n"

    return f"{use_stmt}{prefix}    let {var_name} = get_path();\n{pattern}{suffix}"


@st.composite
def rust_deser_ambiguous_source(draw: st.DrawFn) -> str:
    """Generate Rust code with deserialization where input source is ambiguous.

    The input argument is a plain variable (not a string literal),
    so the scanner cannot determine if it's user-controlled.
    """
    prefix = draw(_AMBIENT_CODE_PREFIX)
    suffix = draw(_AMBIENT_CODE_SUFFIX)
    deser_fn = draw(_DESER_FUNCTIONS)
    var_name = draw(_AMBIGUOUS_VAR_NAMES)

    # Generate deserialization with a variable input
    pattern = draw(
        st.sampled_from(
            [
                f"    let parsed: Config = {deser_fn}({var_name})?;",
                f"    let result = {deser_fn}({var_name}).unwrap();",
                f"    let value: Value = {deser_fn}(&{var_name})?;",
            ]
        )
    )

    return f"{prefix}    let {var_name} = read_input();\n{pattern}{suffix}"


# Combine all ambiguous source strategies
rust_ambiguous_code_strategy = st.one_of(
    rust_ssrf_ambiguous_source(),
    rust_fs_ambiguous_source(),
    rust_deser_ambiguous_source(),
)


# --- Property Tests ---


class TestAmbiguousInputConfidenceCap:
    """Property 21: Ambiguous Input Confidence Cap.

    **Validates: Requirements 2.9**

    For any finding produced by the RustAnalyzer where the data source of the
    flagged pattern is ambiguous (cannot determine whether input is user-controlled),
    the confidence value SHALL NOT exceed 0.70.
    """

    @given(code=rust_ambiguous_code_strategy)
    @settings(max_examples=100)
    def test_ambiguous_findings_confidence_capped_at_070(self, code: str) -> None:
        """All findings from ambiguous input patterns have confidence <= 0.70."""
        analyzer = RustAnalyzer()
        findings = analyzer.scan(code, ArtifactType.MCP, "server.rs")

        # We expect at least one finding from the ambiguous code
        # For each finding related to ambiguous input (SSRF, path traversal, deser),
        # confidence must not exceed 0.70
        ambiguous_risk_ids = {"MCP-S2", "MCP-S9", "MCP-S8"}

        for finding in findings:
            if finding.id in ambiguous_risk_ids:
                assert finding.confidence <= 0.70, (
                    f"Finding {finding.id} has confidence {finding.confidence} > 0.70 "
                    f"for ambiguous input. Evidence: {finding.evidence!r}"
                )

    @given(code=rust_ssrf_ambiguous_source())
    @settings(max_examples=100)
    def test_ssrf_ambiguous_url_confidence_capped(self, code: str) -> None:
        """SSRF findings with ambiguous URL variable have confidence <= 0.70."""
        analyzer = RustAnalyzer()
        findings = analyzer.scan(code, ArtifactType.MCP, "server.rs")

        ssrf_findings = [f for f in findings if f.id == "MCP-S2"]
        for finding in ssrf_findings:
            assert finding.confidence <= 0.70, (
                f"SSRF finding has confidence {finding.confidence} > 0.70 "
                f"for ambiguous URL source. Evidence: {finding.evidence!r}"
            )

    @given(code=rust_fs_ambiguous_source())
    @settings(max_examples=100)
    def test_fs_ambiguous_path_confidence_capped(self, code: str) -> None:
        """File system findings with ambiguous path variable have confidence <= 0.70."""
        analyzer = RustAnalyzer()
        findings = analyzer.scan(code, ArtifactType.MCP, "server.rs")

        fs_findings = [f for f in findings if f.id == "MCP-S9"]
        for finding in fs_findings:
            assert finding.confidence <= 0.70, (
                f"Path traversal finding has confidence {finding.confidence} > 0.70 "
                f"for ambiguous path source. Evidence: {finding.evidence!r}"
            )

    @given(code=rust_deser_ambiguous_source())
    @settings(max_examples=100)
    def test_deser_ambiguous_input_confidence_capped(self, code: str) -> None:
        """Deserialization findings with ambiguous input have confidence <= 0.70."""
        analyzer = RustAnalyzer()
        findings = analyzer.scan(code, ArtifactType.MCP, "server.rs")

        deser_findings = [f for f in findings if f.id == "MCP-S8"]
        for finding in deser_findings:
            assert finding.confidence <= 0.70, (
                f"Deserialization finding has confidence {finding.confidence} > 0.70 "
                f"for ambiguous input source. Evidence: {finding.evidence!r}"
            )
