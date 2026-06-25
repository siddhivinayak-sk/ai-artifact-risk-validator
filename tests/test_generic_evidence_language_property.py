"""Property-based tests for evidence language name inclusion in GenericLanguageScanner.

Feature: extended-mcp-scanning, Property 22: Evidence Language Name Inclusion

**Validates: Requirements 4.6**

Property 22:
- For any finding produced when scanning Go, Ruby, C#, or PHP files, the
  `evidence` field SHALL contain the language name as determined by the
  LanguageDetector.
- Evidence is non-empty and at most 200 characters.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.generic_language_scanner import (
    GenericLanguageScanner,
)

# --- Language name mapping (mirrors _LANGUAGE_NAMES in the scanner) ---

LANGUAGE_NAMES: dict[DetectedLanguage, str] = {
    DetectedLanguage.GO: "Go",
    DetectedLanguage.RUBY: "Ruby",
    DetectedLanguage.CSHARP: "C#",
    DetectedLanguage.PHP: "PHP",
}

# --- Strategies for generating code snippets that trigger findings ---

# Strategy for random identifiers used as variable/function names
_identifier = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=2,
    max_size=12,
).map(lambda s: s if s[0].isalpha() else "v" + s)


@st.composite
def go_code_with_finding(draw: st.DrawFn) -> str:
    """Generate Go code containing patterns that trigger MCP-S1 or MCP-S2."""
    var = draw(_identifier)
    variant = draw(
        st.sampled_from(
            [
                # MCP-S1: os/exec pattern
                f"""package main

import "os/exec"

func run({var} string) {{
    cmd := exec.Command({var})
    cmd.Run()
}}
""",
                # MCP-S1: exec.Command pattern
                f"""package main

import "os/exec"

func execute() {{
    {var} := exec.Command("ls", "-la")
    {var}.Run()
}}
""",
                # MCP-S2: http.Get with variable URL
                f"""package main

import "net/http"

func fetch({var} string) {{
    resp, err := http.Get({var})
    _ = resp
    _ = err
}}
""",
                # MCP-S2: http.Post with variable URL
                f"""package main

import "net/http"

func send({var} string) {{
    resp, err := http.Post({var}, "application/json", nil)
    _ = resp
    _ = err
}}
""",
            ]
        )
    )
    return variant


@st.composite
def ruby_code_with_finding(draw: st.DrawFn) -> str:
    """Generate Ruby code containing patterns that trigger MCP-S1 or MCP-S2."""
    var = draw(_identifier)
    variant = draw(
        st.sampled_from(
            [
                # MCP-S1: system() call
                f"""def run_{var}(cmd)
  system(cmd)
end
""",
                # MCP-S1: backtick execution
                f"""def execute_{var}
  result = `ls -la`
  puts result
end
""",
                # MCP-S1: exec() call
                f"""def do_{var}(command)
  exec(command)
end
""",
                # MCP-S1: %x{{}} execution
                f"""def run_cmd_{var}
  output = %x{{whoami}}
  puts output
end
""",
                # MCP-S2: Net::HTTP
                f"""require 'net/http'

def fetch_{var}(url)
  Net::HTTP.get(URI(url))
end
""",
                # MCP-S2: open-uri
                f"""require 'open-uri'

def download_{var}(url)
  open-uri
end
""",
            ]
        )
    )
    return variant


@st.composite
def csharp_code_with_finding(draw: st.DrawFn) -> str:
    """Generate C# code containing patterns that trigger MCP-S1 or MCP-S2."""
    var = draw(_identifier)
    variant = draw(
        st.sampled_from(
            [
                # MCP-S1: Process.Start
                f"""using System.Diagnostics;

public class {var.capitalize()}Runner {{
    public void Run(string cmd) {{
        Process.Start(cmd);
    }}
}}
""",
                # MCP-S1: Process.StartInfo
                f"""using System.Diagnostics;

public class {var.capitalize()}Executor {{
    public void Execute() {{
        var psi = new Process.StartInfo("cmd.exe");
        psi.Arguments = "/c dir";
    }}
}}
""",
                # MCP-S2: HttpClient instantiation
                f"""using System.Net.Http;

public class {var.capitalize()}Fetcher {{
    public async Task Fetch(string url) {{
        var client = new HttpClient();
        var resp = await client.GetAsync(url);
    }}
}}
""",
                # MCP-S2: WebRequest
                f"""using System.Net;

public class {var.capitalize()}Requester {{
    public void Request(string url) {{
        var req = WebRequest.Create(url);
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def php_code_with_finding(draw: st.DrawFn) -> str:
    """Generate PHP code containing patterns that trigger MCP-S1 or MCP-S2."""
    var = draw(_identifier)
    variant = draw(
        st.sampled_from(
            [
                # MCP-S1: shell_exec()
                f"""<?php
function run_{var}($cmd) {{
    $output = shell_exec($cmd);
    return $output;
}}
""",
                # MCP-S1: exec()
                f"""<?php
function execute_{var}($command) {{
    exec($command, $output, $retval);
    return $output;
}}
""",
                # MCP-S1: system()
                f"""<?php
function sys_{var}($cmd) {{
    system($cmd);
}}
""",
                # MCP-S1: passthru()
                f"""<?php
function pass_{var}($cmd) {{
    passthru($cmd);
}}
""",
                # MCP-S1: popen()
                f"""<?php
function open_{var}($cmd) {{
    $handle = popen($cmd, "r");
    pclose($handle);
}}
""",
                # MCP-S2: file_get_contents with variable
                f"""<?php
function fetch_{var}($url) {{
    $data = file_get_contents($url);
    return $data;
}}
""",
                # MCP-S2: curl_exec()
                f"""<?php
function curl_{var}($url) {{
    $ch = curl_init($url);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}}
""",
            ]
        )
    )
    return variant


# --- Property Tests ---


class TestEvidenceLanguageNameInclusion:
    """Property 22: Evidence Language Name Inclusion.

    Feature: extended-mcp-scanning, Property 22: Evidence Language Name Inclusion

    **Validates: Requirements 4.6**
    """

    scanner = GenericLanguageScanner()

    @given(code=go_code_with_finding())
    @settings(max_examples=100, deadline=None)
    def test_go_findings_contain_language_name_in_evidence(self, code: str) -> None:
        """For any finding produced when scanning Go files, the evidence field
        SHALL contain the language name 'Go'."""
        findings = self.scanner.scan(
            content=code,
            language=DetectedLanguage.GO,
            artifact_type=ArtifactType.MCP,
            artifact_path="server.go",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding for Go code, got none. Code:\n{code}"
        )

        for finding in findings:
            # Evidence must contain the language name
            assert "Go" in finding.evidence, (
                f"Evidence does not contain 'Go': '{finding.evidence}'. Code:\n{code}"
            )
            # Evidence must be non-empty
            assert len(finding.evidence) > 0, f"Evidence is empty for finding {finding.id}"
            # Evidence must be at most 200 characters
            assert len(finding.evidence) <= 200, (
                f"Evidence exceeds 200 chars ({len(finding.evidence)}): '{finding.evidence}'"
            )

    @given(code=ruby_code_with_finding())
    @settings(max_examples=100, deadline=None)
    def test_ruby_findings_contain_language_name_in_evidence(self, code: str) -> None:
        """For any finding produced when scanning Ruby files, the evidence field
        SHALL contain the language name 'Ruby'."""
        findings = self.scanner.scan(
            content=code,
            language=DetectedLanguage.RUBY,
            artifact_type=ArtifactType.MCP,
            artifact_path="server.rb",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding for Ruby code, got none. Code:\n{code}"
        )

        for finding in findings:
            # Evidence must contain the language name
            assert "Ruby" in finding.evidence, (
                f"Evidence does not contain 'Ruby': '{finding.evidence}'. Code:\n{code}"
            )
            # Evidence must be non-empty
            assert len(finding.evidence) > 0, f"Evidence is empty for finding {finding.id}"
            # Evidence must be at most 200 characters
            assert len(finding.evidence) <= 200, (
                f"Evidence exceeds 200 chars ({len(finding.evidence)}): '{finding.evidence}'"
            )

    @given(code=csharp_code_with_finding())
    @settings(max_examples=100, deadline=None)
    def test_csharp_findings_contain_language_name_in_evidence(self, code: str) -> None:
        """For any finding produced when scanning C# files, the evidence field
        SHALL contain the language name 'C#'."""
        findings = self.scanner.scan(
            content=code,
            language=DetectedLanguage.CSHARP,
            artifact_type=ArtifactType.MCP,
            artifact_path="Server.cs",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding for C# code, got none. Code:\n{code}"
        )

        for finding in findings:
            # Evidence must contain the language name
            assert "C#" in finding.evidence, (
                f"Evidence does not contain 'C#': '{finding.evidence}'. Code:\n{code}"
            )
            # Evidence must be non-empty
            assert len(finding.evidence) > 0, f"Evidence is empty for finding {finding.id}"
            # Evidence must be at most 200 characters
            assert len(finding.evidence) <= 200, (
                f"Evidence exceeds 200 chars ({len(finding.evidence)}): '{finding.evidence}'"
            )

    @given(code=php_code_with_finding())
    @settings(max_examples=100, deadline=None)
    def test_php_findings_contain_language_name_in_evidence(self, code: str) -> None:
        """For any finding produced when scanning PHP files, the evidence field
        SHALL contain the language name 'PHP'."""
        findings = self.scanner.scan(
            content=code,
            language=DetectedLanguage.PHP,
            artifact_type=ArtifactType.MCP,
            artifact_path="server.php",
        )

        assert len(findings) >= 1, (
            f"Expected at least one finding for PHP code, got none. Code:\n{code}"
        )

        for finding in findings:
            # Evidence must contain the language name
            assert "PHP" in finding.evidence, (
                f"Evidence does not contain 'PHP': '{finding.evidence}'. Code:\n{code}"
            )
            # Evidence must be non-empty
            assert len(finding.evidence) > 0, f"Evidence is empty for finding {finding.id}"
            # Evidence must be at most 200 characters
            assert len(finding.evidence) <= 200, (
                f"Evidence exceeds 200 chars ({len(finding.evidence)}): '{finding.evidence}'"
            )
