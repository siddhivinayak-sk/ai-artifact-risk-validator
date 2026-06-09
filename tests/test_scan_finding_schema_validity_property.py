"""Property-based tests for ScanFinding schema validity across all scanners.

Feature: extended-mcp-scanning, Property 20: ScanFinding Schema Validity

**Validates: Requirements 7.4**

Property 20:
- For any finding produced by the RustAnalyzer, JavaAnalyzer, enhanced TS/JS
  patterns, GenericLanguageScanner, or DynamicScanner, the finding SHALL pass
  ScanFinding Pydantic model validation:
  - `id` matches pattern `^[A-Z]+-[A-Z]?[0-9]+$`
  - `confidence` is between 0.0 and 1.0
  - `evidence` is non-empty and at most 200 characters
  - `location.line` is a positive integer
"""

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.generic_language_scanner import GenericLanguageScanner
from ai_artifact_risk_validator.scanners.java_analyzer import JavaAnalyzer
from ai_artifact_risk_validator.scanners.rust_analyzer import RustAnalyzer
from ai_artifact_risk_validator.scanners.tsjs_enhanced import TSJSEnhancedPatterns

# --- Regex for ScanFinding id validation ---
VALID_ID_PATTERN = re.compile(r"^[A-Z]+-[A-Z]?[0-9]+$")


def validate_finding_schema(finding: ScanFinding) -> None:
    """Validate that a single ScanFinding passes schema validity checks."""
    # 1. id matches pattern ^[A-Z]+-[A-Z]?[0-9]+$
    assert VALID_ID_PATTERN.match(finding.id), (
        f"Finding id '{finding.id}' does not match pattern ^[A-Z]+-[A-Z]?[0-9]+$"
    )

    # 2. confidence is between 0.0 and 1.0
    assert 0.0 <= finding.confidence <= 1.0, (
        f"Finding confidence {finding.confidence} is not in [0.0, 1.0]"
    )

    # 3. evidence is non-empty and at most 200 characters
    assert len(finding.evidence) > 0, "Finding evidence is empty"
    assert len(finding.evidence) <= 200, (
        f"Finding evidence length {len(finding.evidence)} exceeds 200 characters"
    )

    # 4. location.line is a positive integer
    assert finding.location.line is not None, "Finding location.line is None"
    assert finding.location.line > 0, (
        f"Finding location.line {finding.location.line} is not positive"
    )


# --- Strategies for generating code snippets that produce findings ---


@st.composite
def tsjs_code_with_findings(draw: st.DrawFn) -> str:
    """Generate TS/JS code that will produce at least one finding."""
    variant = draw(
        st.sampled_from(
            [
                # child_process exec
                'const { exec } = require("child_process");\nexec(userInput);',
                # child_process spawn
                'const { spawn } = require("child_process");\nspawn("bash", ["-c", cmd]);',
                # child_process execSync
                'const { execSync } = require("child_process");\nexecSync(command);',
                # new Function with dynamic arg
                "const fn = new Function(userCode);\nfn();",
                # vm module
                'const vm = require("vm");\nvm.runInNewContext(code, sandbox);',
                # vm.Script
                'const vm = require("vm");\nconst script = new vm.Script(userCode);',
                # dynamic URL fetch (SSRF)
                "const res = await fetch(`http://${host}/api/data`);",
                # axios with template literal
                "const res = await axios.get(`${baseUrl}/endpoint`);",
                # node-serialize deserialize
                'const serialize = require("node-serialize");\nconst obj = serialize.deserialize(data);',
                # JSON.parse with variable
                "const data = JSON.parse(userInput);",
                # SQL template literal
                "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);",
                # fs with dynamic path
                "const data = fs.readFileSync(filePath);",
                # fs.writeFile with variable
                "fs.writeFile(outputPath, content, callback);",
            ]
        )
    )
    return variant


@st.composite
def rust_code_with_findings(draw: st.DrawFn) -> str:
    """Generate Rust code that will produce at least one finding."""
    variant = draw(
        st.sampled_from(
            [
                # std::process::Command
                "use std::process::Command;\n\nfn run(cmd: &str) {\n    Command::new(cmd).output().unwrap();\n}",
                # tokio::process::Command
                "use tokio::process::Command;\n\nasync fn run(cmd: &str) {\n    Command::new(cmd).output().await.unwrap();\n}",
                # unsafe with pointer dereference
                "fn danger() {\n    let x = 42;\n    let ptr = &x as *const i32;\n    unsafe {\n        let val = *ptr;\n    }\n}",
                # unsafe with transmute
                "use std::mem;\n\nfn cast() {\n    let x: u32 = 42;\n    unsafe {\n        let y: f32 = std::mem::transmute(x);\n    }\n}",
                # unsafe with extern "C"
                'fn ffi_call() {\n    unsafe {\n        extern "C" {\n            fn puts(s: *const i8) -> i32;\n        }\n    }\n}',
                # reqwest with dynamic URL
                "async fn fetch(url: &str) {\n    let resp = reqwest::get(url).await.unwrap();\n}",
                # serde_json with dynamic input
                "fn parse(data: &str) {\n    let val: Value = serde_json::from_str(data).unwrap();\n}",
                # format! with SQL
                'fn query(user_id: &str) {\n    let sql = format!("SELECT * FROM users WHERE id = {}", user_id);\n}',
            ]
        )
    )
    return variant


@st.composite
def java_code_with_findings(draw: st.DrawFn) -> str:
    """Generate Java code that will produce at least one finding."""
    variant = draw(
        st.sampled_from(
            [
                # Runtime.exec
                "public class Tool {\n    public void run(String cmd) {\n        Runtime.getRuntime().exec(cmd);\n    }\n}",
                # ProcessBuilder
                "public class Tool {\n    public void run(String cmd) {\n        new ProcessBuilder(cmd).start();\n    }\n}",
                # ScriptEngine.eval
                'import javax.script.*;\npublic class Tool {\n    public void run(String code) {\n        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");\n        engine.eval(code);\n    }\n}',
                # ObjectInputStream
                "import java.io.*;\npublic class Tool {\n    public void read(InputStream is) {\n        ObjectInputStream ois = new ObjectInputStream(is);\n        Object obj = ois.readObject();\n    }\n}",
                # XStream
                "import com.thoughtworks.xstream.*;\npublic class Tool {\n    public void parse(String xml) {\n        XStream xstream = new XStream();\n        Object obj = xstream.fromXML(xml);\n    }\n}",
                # JNDI lookup with non-constant arg (pattern requires InitialContext.lookup on same line)
                "import javax.naming.*;\npublic class Tool {\n    public void lookup(String name) {\n        new InitialContext().lookup(name);\n    }\n}",
                # SQL concatenation
                'public class Tool {\n    public void query(String id) {\n        String sql = "SELECT * FROM users WHERE id = " + id;\n    }\n}',
                # HttpURLConnection with dynamic URL
                "import java.net.*;\npublic class Tool {\n    public void fetch(String url) {\n        URL u = new URL(url);\n        HttpURLConnection conn = (HttpURLConnection) u.openConnection();\n    }\n}",
            ]
        )
    )
    return variant


@st.composite
def generic_language_code_with_findings(draw: st.DrawFn) -> tuple[str, DetectedLanguage]:
    """Generate code for Go/Ruby/C#/PHP that will produce at least one finding."""
    choice = draw(
        st.sampled_from(
            [
                # Go: os/exec
                (
                    'package main\n\nimport "os/exec"\n\nfunc run(cmd string) {\n    exec.Command(cmd).Run()\n}',
                    DetectedLanguage.GO,
                ),
                # Go: http.Get with variable
                (
                    'package main\n\nimport "net/http"\n\nfunc fetch(url string) {\n    http.Get(url)\n}',
                    DetectedLanguage.GO,
                ),
                # Ruby: system()
                ("def run(cmd)\n  system(cmd)\nend", DetectedLanguage.RUBY),
                # Ruby: backtick execution
                ("def run(cmd)\n  result = `#{cmd}`\nend", DetectedLanguage.RUBY),
                # Ruby: Net::HTTP
                (
                    'require "net/http"\n\ndef fetch(url)\n  Net::HTTP.get(URI(url))\nend',
                    DetectedLanguage.RUBY,
                ),
                # C#: Process.Start
                (
                    "using System.Diagnostics;\n\nclass Tool {\n    void Run(string cmd) {\n        Process.Start(cmd);\n    }\n}",
                    DetectedLanguage.CSHARP,
                ),
                # C#: HttpClient with variable
                (
                    "using System.Net.Http;\n\nclass Tool {\n    async void Fetch(string url) {\n        var client = new HttpClient();\n        await client.GetAsync(url);\n    }\n}",
                    DetectedLanguage.CSHARP,
                ),
                # PHP: shell_exec
                (
                    "<?php\nfunction run($cmd) {\n    $output = shell_exec($cmd);\n}",
                    DetectedLanguage.PHP,
                ),
                # PHP: exec()
                ("<?php\nfunction run($cmd) {\n    exec($cmd, $output);\n}", DetectedLanguage.PHP),
                # PHP: file_get_contents with variable
                (
                    "<?php\nfunction fetch($url) {\n    $data = file_get_contents($url);\n}",
                    DetectedLanguage.PHP,
                ),
            ]
        )
    )
    return choice


# --- Property Tests ---


class TestScanFindingSchemaValidity:
    """Property 20: ScanFinding Schema Validity.

    Feature: extended-mcp-scanning, Property 20: ScanFinding Schema Validity

    **Validates: Requirements 7.4**
    """

    tsjs_scanner = TSJSEnhancedPatterns()
    rust_analyzer = RustAnalyzer()
    java_analyzer = JavaAnalyzer()
    generic_scanner = GenericLanguageScanner()

    @given(code=tsjs_code_with_findings())
    @settings(max_examples=100)
    def test_tsjs_findings_pass_schema_validation(self, code: str) -> None:
        """For any finding produced by TSJSEnhancedPatterns, the finding SHALL
        pass ScanFinding schema validation."""
        findings = self.tsjs_scanner.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/index.ts",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding from TSJS scanner for code:\n{code}"
        )

        for finding in findings:
            validate_finding_schema(finding)

    @given(code=rust_code_with_findings())
    @settings(max_examples=100)
    def test_rust_findings_pass_schema_validation(self, code: str) -> None:
        """For any finding produced by RustAnalyzer, the finding SHALL
        pass ScanFinding schema validation."""
        findings = self.rust_analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main.rs",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding from Rust analyzer for code:\n{code}"
        )

        for finding in findings:
            validate_finding_schema(finding)

    @given(code=java_code_with_findings())
    @settings(max_examples=100)
    def test_java_findings_pass_schema_validation(self, code: str) -> None:
        """For any finding produced by JavaAnalyzer, the finding SHALL
        pass ScanFinding schema validation."""
        findings = self.java_analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/Main.java",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding from Java analyzer for code:\n{code}"
        )

        for finding in findings:
            validate_finding_schema(finding)

    @given(code_and_lang=generic_language_code_with_findings())
    @settings(max_examples=100)
    def test_generic_scanner_findings_pass_schema_validation(
        self, code_and_lang: tuple[str, DetectedLanguage]
    ) -> None:
        """For any finding produced by GenericLanguageScanner, the finding SHALL
        pass ScanFinding schema validation."""
        code, language = code_and_lang

        # Determine file extension based on language
        ext_map = {
            DetectedLanguage.GO: "main.go",
            DetectedLanguage.RUBY: "server.rb",
            DetectedLanguage.CSHARP: "Tool.cs",
            DetectedLanguage.PHP: "server.php",
        }
        artifact_path = f"server/src/{ext_map.get(language, 'unknown.txt')}"

        findings = self.generic_scanner.scan(
            content=code,
            language=language,
            artifact_type=ArtifactType.MCP,
            artifact_path=artifact_path,
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding from GenericLanguageScanner for "
            f"{language.value} code:\n{code}"
        )

        for finding in findings:
            validate_finding_schema(finding)
