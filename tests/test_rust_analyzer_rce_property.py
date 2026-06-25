"""Property-based tests for RustAnalyzer RCE pattern detection.

Feature: extended-mcp-scanning, Property 2: RCE Pattern Detection Across Languages (Rust subset)

**Validates: Requirements 2.2, 2.3**

Property 2 (Rust subset):
- For any Rust source file containing std::process::Command::new or
  tokio::process::Command::new, the RustAnalyzer SHALL produce at least one
  ScanFinding with id="MCP-S1" and confidence between 0.85 and 0.95.
- For any Rust source file containing unsafe blocks with FFI/pointer operations
  (raw pointer dereference, transmute, extern "C"), the RustAnalyzer SHALL
  produce at least one ScanFinding with id="MCP-S1" and confidence between
  0.65 and 0.75.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.rust_analyzer import RustAnalyzer

# --- Strategies for generating Rust code snippets ---

# Strategy for random valid Rust identifiers
rust_identifier = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=1,
    max_size=15,
).map(lambda s: s if s[0].isalpha() else "f" + s)

# Strategy for random variable names used as command arguments
rust_variable_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=2,
    max_size=10,
).map(lambda s: s if s[0].isalpha() else "cmd" + s)


@st.composite
def rust_std_process_command_code(draw: st.DrawFn) -> str:
    """Generate Rust code containing std::process::Command::new usage."""
    fn_name = draw(rust_identifier)
    var_name = draw(rust_variable_name)
    arg = draw(rust_variable_name)

    # Pick a variant of Command usage
    variant = draw(
        st.sampled_from(
            [
                # Full path with dynamic arg
                f"""use std::io;

fn {fn_name}({arg}: &str) {{
    let output = std::process::Command::new({arg})
        .arg("--version")
        .output()
        .expect("failed");
    println!("{{:?}}", output);
}}
""",
                # Full path with string literal arg
                f"""use std::io;

fn {fn_name}() {{
    let {var_name} = std::process::Command::new("ls")
        .arg("-la")
        .output()
        .expect("failed");
}}
""",
                # With use import and dynamic arg
                f"""use std::process::Command;

fn {fn_name}({arg}: &str) {{
    let {var_name} = Command::new({arg})
        .output()
        .expect("failed to execute");
}}
""",
                # With use import and literal arg
                f"""use std::process::Command;

fn {fn_name}() {{
    let {var_name} = Command::new("echo")
        .arg("hello")
        .status()
        .unwrap();
}}
""",
            ]
        )
    )
    return variant


@st.composite
def rust_tokio_process_command_code(draw: st.DrawFn) -> str:
    """Generate Rust code containing tokio::process::Command::new usage."""
    fn_name = draw(rust_identifier)
    var_name = draw(rust_variable_name)
    arg = draw(rust_variable_name)

    variant = draw(
        st.sampled_from(
            [
                # Full path with dynamic arg
                f"""use tokio::io;

async fn {fn_name}({arg}: &str) {{
    let {var_name} = tokio::process::Command::new({arg})
        .output()
        .await
        .expect("failed");
}}
""",
                # Full path with literal arg
                f"""use tokio::io;

async fn {fn_name}() {{
    let {var_name} = tokio::process::Command::new("cat")
        .arg("/etc/hosts")
        .output()
        .await
        .unwrap();
}}
""",
                # With use import and dynamic arg
                f"""use tokio::process::Command;

async fn {fn_name}({arg}: &str) {{
    let {var_name} = Command::new({arg})
        .kill_on_drop(true)
        .output()
        .await
        .expect("failed");
}}
""",
                # With use import and literal
                f"""use tokio::process::Command;

async fn {fn_name}() {{
    let {var_name} = Command::new("whoami")
        .output()
        .await
        .unwrap();
}}
""",
            ]
        )
    )
    return variant


@st.composite
def rust_unsafe_ffi_pointer_code(draw: st.DrawFn) -> str:
    """Generate Rust code containing unsafe blocks with FFI/pointer operations."""
    fn_name = draw(rust_identifier)
    var_name = draw(rust_variable_name)

    variant = draw(
        st.sampled_from(
            [
                # Raw pointer dereference
                f"""fn {fn_name}() {{
    let {var_name} = 42;
    let ptr = &{var_name} as *const i32;
    unsafe {{
        let val = *ptr;
        println!("{{val}}");
    }}
}}
""",
                # transmute usage
                f"""use std::mem;

fn {fn_name}() {{
    let {var_name}: u32 = 42;
    unsafe {{
        let result: f32 = std::mem::transmute({var_name});
        println!("{{result}}");
    }}
}}
""",
                # transmute with shorter path
                f"""use std::mem::transmute;

fn {fn_name}() {{
    let {var_name}: [u8; 4] = [0, 0, 0, 0];
    unsafe {{
        let val: u32 = transmute({var_name});
        println!("{{val}}");
    }}
}}
""",
                # extern "C" block (FFI)
                f"""fn {fn_name}() {{
    unsafe {{
        extern "C" {{
            fn printf(format: *const i8, ...) -> i32;
        }}
        let msg = b"hello\\0";
        printf(msg.as_ptr() as *const i8);
    }}
}}
""",
                # extern "C" fn
                f"""fn {fn_name}() {{
    unsafe {{
        extern "C" fn callback(x: i32) -> i32 {{
            x + 1
        }}
        let {var_name} = callback(5);
    }}
}}
""",
                # libc usage
                f"""use libc;

fn {fn_name}() {{
    unsafe {{
        let pid = libc::getpid();
        println!("PID: {{}}", pid);
    }}
}}
""",
                # ptr operations
                f"""fn {fn_name}() {{
    let {var_name} = vec![1u8, 2, 3, 4];
    unsafe {{
        let ptr = {var_name}.as_ptr();
        let val = ptr::read(ptr);
        println!("{{val}}");
    }}
}}
""",
                # cast to raw pointer
                f"""fn {fn_name}() {{
    let {var_name}: i32 = 10;
    unsafe {{
        let raw = &{var_name} as *const i32;
        let mutable_raw = raw as *mut i32;
        *mutable_raw = 20;
    }}
}}
""",
            ]
        )
    )
    return variant


# --- Property Tests ---


class TestRustRCEPatternDetection:
    """Property 2 (Rust subset): RCE Pattern Detection.

    Feature: extended-mcp-scanning, Property 2: RCE Pattern Detection Across Languages (Rust subset)

    **Validates: Requirements 2.2, 2.3**
    """

    analyzer = RustAnalyzer()

    @given(code=rust_std_process_command_code())
    @settings(max_examples=100, deadline=None)
    def test_std_process_command_detected_as_mcp_s1(self, code: str) -> None:
        """For any Rust source file containing std::process::Command::new,
        the RustAnalyzer SHALL produce at least one ScanFinding with
        id="MCP-S1" and confidence between 0.85 and 0.95."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main.rs",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for std::process::Command code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )

        # At least one finding should have confidence in [0.85, 0.95]
        valid_confidence = [f for f in mcp_s1_findings if 0.85 <= f.confidence <= 0.95]
        assert len(valid_confidence) >= 1, (
            f"Expected at least one MCP-S1 finding with confidence in [0.85, 0.95], "
            f"got confidences: {[f.confidence for f in mcp_s1_findings]}. Code:\n{code}"
        )

    @given(code=rust_tokio_process_command_code())
    @settings(max_examples=100, deadline=None)
    def test_tokio_process_command_detected_as_mcp_s1(self, code: str) -> None:
        """For any Rust source file containing tokio::process::Command::new,
        the RustAnalyzer SHALL produce at least one ScanFinding with
        id="MCP-S1" and confidence between 0.85 and 0.95."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main.rs",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for tokio::process::Command code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )

        # At least one finding should have confidence in [0.85, 0.95]
        valid_confidence = [f for f in mcp_s1_findings if 0.85 <= f.confidence <= 0.95]
        assert len(valid_confidence) >= 1, (
            f"Expected at least one MCP-S1 finding with confidence in [0.85, 0.95], "
            f"got confidences: {[f.confidence for f in mcp_s1_findings]}. Code:\n{code}"
        )

    @given(code=rust_unsafe_ffi_pointer_code())
    @settings(max_examples=100, deadline=None)
    def test_unsafe_ffi_pointer_detected_as_mcp_s1(self, code: str) -> None:
        """For any Rust source file containing unsafe blocks with FFI/pointer
        operations (raw pointer dereference, transmute, extern "C"), the
        RustAnalyzer SHALL produce at least one ScanFinding with id="MCP-S1"
        and confidence between 0.65 and 0.75."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/lib.rs",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for unsafe FFI/pointer code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )

        # At least one finding should have confidence in [0.65, 0.75]
        valid_confidence = [f for f in mcp_s1_findings if 0.65 <= f.confidence <= 0.75]
        assert len(valid_confidence) >= 1, (
            f"Expected at least one MCP-S1 finding with confidence in [0.65, 0.75], "
            f"got confidences: {[f.confidence for f in mcp_s1_findings]}. Code:\n{code}"
        )
