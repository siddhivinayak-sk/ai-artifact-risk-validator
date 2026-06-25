"""Unit tests for FP reduction phase 2 changes.

Covers:
1. CodeAudit: Markdown-aware scanning (_scan_markdown path)
2. CodeAudit: Improved _is_inline_code_span with template/annotation patterns
3. CodeAudit: _RE_DANGEROUS_FUNCS regex excludes re.compile() in non-Python
4. PermAudit: Tightened "Dangerous system command" (halt) pattern
5. PermAudit: Tightened "File truncation" (truncate) pattern
6. LanguageDetector: .md recognized as MARKDOWN
"""

from __future__ import annotations

import pytest

from ai_artifact_risk_validator.models import ArtifactType
from ai_artifact_risk_validator.models.language import DetectedLanguage
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
from ai_artifact_risk_validator.scanners.language_detector import LanguageDetector
from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def code_audit() -> CodeAuditScanner:
    """Create a CodeAuditScanner instance."""
    return CodeAuditScanner()


@pytest.fixture
def perm_audit() -> PermAuditScanner:
    """Create a PermAuditScanner instance."""
    return PermAuditScanner()


@pytest.fixture
def lang_detector() -> LanguageDetector:
    """Create a LanguageDetector instance."""
    return LanguageDetector()


# ===========================================================================
# 1. LanguageDetector: Markdown detection
# ===========================================================================


class TestLanguageDetectorMarkdown:
    """Tests for .md/.mdx extension recognition as MARKDOWN."""

    def test_md_extension_detected(self, lang_detector: LanguageDetector) -> None:
        """Files with .md extension are detected as MARKDOWN."""
        result = lang_detector.detect("requirements.md", "")
        assert result == DetectedLanguage.MARKDOWN

    def test_mdx_extension_detected(self, lang_detector: LanguageDetector) -> None:
        """Files with .mdx extension are detected as MARKDOWN."""
        result = lang_detector.detect("component.mdx", "# Title")
        assert result == DetectedLanguage.MARKDOWN

    def test_md_case_insensitive(self, lang_detector: LanguageDetector) -> None:
        """Extension detection is case-insensitive."""
        result = lang_detector.detect("README.MD", "")
        assert result == DetectedLanguage.MARKDOWN

    def test_py_still_python(self, lang_detector: LanguageDetector) -> None:
        """Python files still detected correctly after adding markdown."""
        result = lang_detector.detect("script.py", "")
        assert result == DetectedLanguage.PYTHON


# ===========================================================================
# 2. CodeAudit: Markdown-aware scanning
# ===========================================================================


class TestCodeAuditMarkdownScanning:
    """Tests for the new _scan_markdown path used for .md files."""

    def test_plain_prose_no_findings(self, code_audit: CodeAuditScanner) -> None:
        """Plain prose in .md produces no findings."""
        content = "This is a design document about the coverage dashboard.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "design.md")
        assert len(findings) == 0

    def test_eval_in_fenced_code_block_detected(self, code_audit: CodeAuditScanner) -> None:
        """eval() inside a fenced code block is still detected."""
        content = "```python\nresult = eval(user_input)\n```\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "example.md")
        assert len(findings) >= 1
        assert any("eval" in f.evidence for f in findings)

    def test_subprocess_in_fenced_code_block_detected(self, code_audit: CodeAuditScanner) -> None:
        """subprocess.run() inside a fenced code block is detected."""
        content = "```python\nimport subprocess\nsubprocess.run(cmd, shell=True)\n```\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "example.md")
        assert len(findings) >= 1
        assert any("subprocess.run" in f.evidence for f in findings)

    def test_compile_outside_code_block_not_detected(self, code_audit: CodeAuditScanner) -> None:
        """The word 'compile' in prose .md does NOT produce a finding."""
        content = "You need to compile the regex pattern first.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "guide.md")
        # Should not flag prose usage of 'compile'
        compile_findings = [f for f in findings if "compile" in f.evidence.lower()]
        assert len(compile_findings) == 0

    def test_format_in_prose_not_detected(self, code_audit: CodeAuditScanner) -> None:
        """The word 'format' in prose .md does NOT produce a destructive finding."""
        content = "The output format is JSON.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "guide.md")
        destructive = [f for f in findings if "destructive" in f.description.lower()]
        assert len(destructive) == 0

    def test_halt_in_prose_not_detected(self, code_audit: CodeAuditScanner) -> None:
        """The word 'halt' in prose .md does NOT produce a destructive finding."""
        content = "## Halt the pipeline\n\nWhen errors occur, halt processing.\n"
        findings = code_audit.scan(content, ArtifactType.AGENT, "guide.md")
        halt_findings = [
            f
            for f in findings
            if "halt" in f.evidence.lower() and "destructive" in f.description.lower()
        ]
        assert len(halt_findings) == 0

    def test_destructive_keyword_in_code_block_detected(self, code_audit: CodeAuditScanner) -> None:
        """Destructive keywords inside code blocks are still detected."""
        content = "```bash\n$ drop database production\n```\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "deploy.md")
        destructive = [
            f
            for f in findings
            if "destructive" in f.description.lower() or "drop" in f.evidence.lower()
        ]
        assert len(destructive) >= 1

    def test_shell_prompt_halt_still_detected(self, code_audit: CodeAuditScanner) -> None:
        """$ halt on its own line (shell prompt context) is detected."""
        content = "$ halt\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "commands.md")
        halt_findings = [
            f
            for f in findings
            if "halt" in f.evidence.lower() or "destructive" in f.description.lower()
        ]
        assert len(halt_findings) >= 1

    def test_re_compile_in_prose_not_detected(self, code_audit: CodeAuditScanner) -> None:
        """re.compile() mentioned in prose .md does NOT produce a finding."""
        content = "Use re.compile() to pre-compile regex patterns for better performance.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "guide.md")
        compile_findings = [f for f in findings if "compile" in f.evidence.lower()]
        assert len(compile_findings) == 0

    def test_path_function_in_prose_not_detected(self, code_audit: CodeAuditScanner) -> None:
        """Path() mentioned in prose .md does NOT produce a finding."""
        content = "Use Path(input_dir) from pathlib for cross-platform paths.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "guide.md")
        path_findings = [f for f in findings if "Path(" in f.evidence]
        assert len(path_findings) == 0

    def test_encoded_exec_in_code_block_detected(self, code_audit: CodeAuditScanner) -> None:
        """Encoded execution chains in code blocks are still detected."""
        content = "```python\nexec(base64.b64decode(payload))\n```\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "malicious.md")
        assert len(findings) >= 1
        assert any(f.id == "AST-S8" or "exec" in f.evidence for f in findings)


# ===========================================================================
# 3. CodeAudit: _is_inline_code_span improvements
# ===========================================================================


class TestInlineCodeSpanDetection:
    """Tests for improved _is_inline_code_span false positive reduction."""

    def test_template_placeholder_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Angle-bracket templates like <spec-name>/R<n> are inline code."""
        assert code_audit._is_inline_code_span("<spec-name>/R<n> AC<m>") is True

    def test_type_annotation_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Python type annotations are inline code."""
        assert code_audit._is_inline_code_span("str | None") is True

    def test_variable_declaration_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Variable declarations are inline code."""
        assert code_audit._is_inline_code_span("spec_name: str | None = None") is True

    def test_dotted_identifier_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Dotted identifiers like module.function are inline code."""
        assert code_audit._is_inline_code_span("os.path.join") is True

    def test_quoted_string_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Quoted strings are inline code."""
        assert code_audit._is_inline_code_span('"<spec_name>/R<req_num> AC<ac_num>"') is True

    def test_bold_markdown_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Bold markdown inside backticks is inline code."""
        assert code_audit._is_inline_code_span("**Validates: delivery-signoff/R<n> AC<m>**") is True

    def test_filename_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Filenames are inline code."""
        assert code_audit._is_inline_code_span("conftest.py") is True
        assert code_audit._is_inline_code_span("mcp.json") is True
        assert code_audit._is_inline_code_span(".kiro/steering/project.md") is True

    def test_flag_option_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Command-line flags are inline code (not commands)."""
        assert code_audit._is_inline_code_span("--channel") is True
        assert code_audit._is_inline_code_span("--validate") is True
        assert code_audit._is_inline_code_span("-rf") is True

    def test_numbered_requirement_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Numbered requirements (e.g., '1. THE ...') are inline code."""
        assert code_audit._is_inline_code_span("1. THE Starter_Kit SHALL deploy") is True

    def test_single_word_recognized(self, code_audit: CodeAuditScanner) -> None:
        """Single words are inline code."""
        assert code_audit._is_inline_code_span("override_mode") is True
        assert code_audit._is_inline_code_span("Channel_Adapter") is True

    def test_shell_command_with_rm_not_inline(self, code_audit: CodeAuditScanner) -> None:
        """rm -rf /tmp is a shell command, not inline code."""
        assert code_audit._is_inline_code_span("rm -rf /tmp") is False

    def test_shell_command_with_pipe_not_inline(self, code_audit: CodeAuditScanner) -> None:
        """Commands with pipes are not inline code."""
        assert code_audit._is_inline_code_span("cat file | grep pattern") is False

    def test_shell_command_with_redirect_not_inline(self, code_audit: CodeAuditScanner) -> None:
        """Commands with I/O redirection are not inline code (but templates are safe)."""
        assert code_audit._is_inline_code_span("echo hello > output.txt") is False

    def test_git_command_not_inline(self, code_audit: CodeAuditScanner) -> None:
        """Multi-token git command is not inline code."""
        assert code_audit._is_inline_code_span("git push origin main") is False

    def test_empty_content_is_inline(self, code_audit: CodeAuditScanner) -> None:
        """Empty content is treated as inline code."""
        assert code_audit._is_inline_code_span("") is True

    def test_very_long_content_is_inline(self, code_audit: CodeAuditScanner) -> None:
        """Very long content (>1000 chars) is treated as inline code."""
        assert code_audit._is_inline_code_span("x" * 1500) is True


# ===========================================================================
# 4. CodeAudit: _RE_DANGEROUS_FUNCS regex improvement
# ===========================================================================


class TestDangerousFuncsRegexImprovement:
    """Tests that _RE_DANGEROUS_FUNCS no longer matches re.compile() in regex path."""

    def test_re_compile_not_matched_in_non_python(self, code_audit: CodeAuditScanner) -> None:
        """re.compile() in non-Python content does not trigger a finding."""
        content = "pattern = re.compile(r'\\d+')\n"
        # Use .ts extension to force regex path
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "helper.ts")
        compile_findings = [
            f for f in findings if "compile" in f.evidence.lower() and "Dangerous" in f.description
        ]
        assert len(compile_findings) == 0

    def test_standalone_compile_still_matched(self, code_audit: CodeAuditScanner) -> None:
        """Standalone compile() IS detected as dangerous."""
        content = "result = compile(source, '<string>', 'exec')\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "plugin.ts")
        compile_findings = [f for f in findings if "compile" in f.evidence.lower()]
        assert len(compile_findings) >= 1

    def test_eval_still_matched(self, code_audit: CodeAuditScanner) -> None:
        """eval() is still detected by the regex."""
        content = "result = eval(userInput);\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "plugin.js")
        eval_findings = [f for f in findings if "eval" in f.evidence.lower()]
        assert len(eval_findings) >= 1

    def test_exec_still_matched(self, code_audit: CodeAuditScanner) -> None:
        """exec() is still detected by the regex."""
        content = "exec(code_string)\n"
        findings = code_audit.scan(content, ArtifactType.MCP, "server.ts")
        exec_findings = [f for f in findings if "exec" in f.evidence.lower()]
        assert len(exec_findings) >= 1

    def test_module_dot_compile_not_matched(self, code_audit: CodeAuditScanner) -> None:
        """Any module.compile() pattern is excluded by the negative lookbehind."""
        content = "regex.compile(pattern)\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "helper.ts")
        compile_findings = [
            f for f in findings if "compile" in f.evidence.lower() and "Dangerous" in f.description
        ]
        assert len(compile_findings) == 0


# ===========================================================================
# 5. CodeAudit: Markdown backtick FP reduction (end-to-end)
# ===========================================================================


class TestMarkdownBacktickFPReduction:
    """End-to-end tests proving FP reduction for .md files with backtick content."""

    def test_spec_template_backtick_no_finding(self, code_audit: CodeAuditScanner) -> None:
        """Backtick template `<spec-name>/R<n> AC<m>` in .md produces no finding."""
        content = "Use the format `<spec-name>/R<n> AC<m>` for traceability.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "requirements.md")
        assert len(findings) == 0

    def test_type_annotation_backtick_no_finding(self, code_audit: CodeAuditScanner) -> None:
        """Backtick type annotation `str | None` in .md produces no finding."""
        content = "The field type is `str | None`.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "design.md")
        assert len(findings) == 0

    def test_filename_backtick_no_finding(self, code_audit: CodeAuditScanner) -> None:
        """Backtick filename `.kiro/steering/project.md` produces no finding."""
        content = "Edit the file `.kiro/steering/project.md` to add rules.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "readme.md")
        assert len(findings) == 0

    def test_option_flag_backtick_no_finding(self, code_audit: CodeAuditScanner) -> None:
        """Backtick option flag `--validate` produces no finding."""
        content = "Run with the `--validate` flag to check.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "usage.md")
        assert len(findings) == 0

    def test_shell_command_backtick_produces_finding(self, code_audit: CodeAuditScanner) -> None:
        """Backtick shell command `rm -rf /tmp/build` DOES produce a finding."""
        content = "Run `rm -rf /tmp/build` to clean up.\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "cleanup.md")
        assert len(findings) >= 1
        assert any("rm -rf" in f.evidence for f in findings)

    def test_multiple_safe_backticks_no_findings(self, code_audit: CodeAuditScanner) -> None:
        """Multiple safe backtick spans in a single .md produce no findings."""
        content = (
            "Use `spec_name: str | None = None` as the parameter.\n"
            "Deploy to `.kiro/hooks/` directory.\n"
            "Set `--channel kiro-ide` for the IDE adapter.\n"
            "Reference format: `<spec-name>/R<n> AC<m>`.\n"
        )
        findings = code_audit.scan(content, ArtifactType.SKILL, "vision.md")
        assert len(findings) == 0

    def test_vision_doc_numbered_requirements_no_findings(
        self, code_audit: CodeAuditScanner
    ) -> None:
        """Numbered requirements starting with digits in backticks produce no findings."""
        content = (
            "The requirements:\n"
            "`1. THE Starter_Kit SHALL deploy a .kiro/steering/ file`\n"
            "`2. THE Deployer SHALL accept a --channel parameter`\n"
        )
        findings = code_audit.scan(content, ArtifactType.SKILL, "vision.md")
        assert len(findings) == 0


# ===========================================================================
# 6. PermAudit: Tightened "halt" pattern
# ===========================================================================


class TestPermAuditHaltFPReduction:
    """Tests for PermAudit no longer flagging 'halt' in prose."""

    def test_halt_in_prose_not_flagged(self, perm_audit: PermAuditScanner) -> None:
        """The word 'halt' in prose does NOT produce a finding."""
        content = "When an error is detected, halt the pipeline and report.\n"
        findings = perm_audit.scan(content, ArtifactType.AGENT, "orchestrator.md")
        halt_findings = [
            f
            for f in findings
            if "halt" in f.evidence.lower() and "system" in f.description.lower()
        ]
        assert len(halt_findings) == 0

    def test_capitalized_halt_in_prose_not_flagged(self, perm_audit: PermAuditScanner) -> None:
        """Capitalized 'Halt' in prose does NOT produce a finding."""
        content = "## Halt Conditions\n\nHalt execution when quality drops below threshold.\n"
        findings = perm_audit.scan(content, ArtifactType.AGENT, "steering.md")
        halt_findings = [
            f
            for f in findings
            if "halt" in f.evidence.lower() and "system" in f.description.lower()
        ]
        assert len(halt_findings) == 0

    def test_halt_with_flag_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """halt -p (with a command flag) IS still detected."""
        content = "halt -p\n"
        findings = perm_audit.scan(content, ArtifactType.AGENT, "dangerous.md")
        halt_findings = [f for f in findings if "halt" in f.evidence.lower()]
        assert len(halt_findings) >= 1

    def test_shutdown_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """shutdown command is still detected."""
        content = "shutdown -h now\n"
        findings = perm_audit.scan(content, ArtifactType.AGENT, "dangerous.md")
        shutdown_findings = [
            f
            for f in findings
            if "shutdown" in f.evidence.lower() or "system" in f.description.lower()
        ]
        assert len(shutdown_findings) >= 1

    def test_reboot_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """reboot command is still detected."""
        content = "reboot\n"
        findings = perm_audit.scan(content, ArtifactType.SKILL, "skill.md")
        reboot_findings = [
            f
            for f in findings
            if "reboot" in f.evidence.lower() or "system" in f.description.lower()
        ]
        assert len(reboot_findings) >= 1

    def test_poweroff_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """poweroff command is still detected."""
        content = "poweroff\n"
        findings = perm_audit.scan(content, ArtifactType.SKILL, "skill.md")
        poweroff_findings = [
            f
            for f in findings
            if "poweroff" in f.evidence.lower() or "system" in f.description.lower()
        ]
        assert len(poweroff_findings) >= 1


# ===========================================================================
# 7. PermAudit: Tightened "truncate" pattern
# ===========================================================================


class TestPermAuditTruncateFPReduction:
    """Tests for PermAudit no longer flagging 'truncate' in prose."""

    def test_truncate_in_prose_not_flagged(self, perm_audit: PermAuditScanner) -> None:
        """The word 'truncate' in prose does NOT produce a truncation finding."""
        content = "You may want to truncate the output for readability.\n"
        findings = perm_audit.scan(content, ArtifactType.AGENT, "guide.md")
        trunc_findings = [
            f
            for f in findings
            if "truncat" in f.evidence.lower() and "truncation" in f.description.lower()
        ]
        assert len(trunc_findings) == 0

    def test_truncate_file_path_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """truncate /var/log/syslog IS still detected."""
        content = "truncate /var/log/syslog\n"
        findings = perm_audit.scan(content, ArtifactType.SKILL, "cleanup.md")
        trunc_findings = [f for f in findings if "truncat" in f.evidence.lower()]
        assert len(trunc_findings) >= 1

    def test_truncate_function_call_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """truncate('file') python call IS still detected."""
        content = "truncate('/tmp/data.log'\n"
        findings = perm_audit.scan(content, ArtifactType.SKILL, "skill.py")
        trunc_findings = [f for f in findings if "truncat" in f.evidence.lower()]
        assert len(trunc_findings) >= 1

    def test_redirect_to_dev_null_still_flagged(self, perm_audit: PermAuditScanner) -> None:
        """> /dev/null redirect IS still detected."""
        content = "output > /dev/null\n"
        findings = perm_audit.scan(content, ArtifactType.HOOK, "hook.yaml")
        trunc_findings = [f for f in findings if "truncation" in f.description.lower()]
        assert len(trunc_findings) >= 1

    def test_truncate_table_still_detected_by_db_pattern(
        self, perm_audit: PermAuditScanner
    ) -> None:
        """TRUNCATE TABLE is still detected by the database destructive pattern."""
        content = "TRUNCATE TABLE audit_log;\n"
        findings = perm_audit.scan(content, ArtifactType.PLUGIN, "db_plugin.py")
        db_findings = [
            f for f in findings if "Database" in f.description or "TRUNCATE" in f.evidence
        ]
        assert len(db_findings) >= 1


# ===========================================================================
# 8. Backward compatibility: Python .py files unchanged
# ===========================================================================


class TestBackwardCompatibilityPythonFiles:
    """Ensures .py file scanning behavior is unchanged."""

    def test_compile_in_py_still_detected_by_ast(self, code_audit: CodeAuditScanner) -> None:
        """compile() in .py files is still caught by AST analysis."""
        content = "compiled = compile(source, '<string>', 'exec')\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "plugin.py")
        assert any(f.evidence == "compile" for f in findings)

    def test_eval_in_py_still_detected(self, code_audit: CodeAuditScanner) -> None:
        """eval() in .py files is still caught."""
        content = "result = eval(user_input)\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "skill.py")
        assert any("eval" in f.evidence for f in findings)

    def test_subprocess_in_py_still_detected(self, code_audit: CodeAuditScanner) -> None:
        """subprocess calls in .py files are still caught."""
        content = "import subprocess\nsubprocess.call(['ls', '-la'])\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "skill.py")
        assert any("subprocess" in f.evidence for f in findings)

    def test_safe_py_code_no_findings(self, code_audit: CodeAuditScanner) -> None:
        """Safe Python code produces no findings."""
        content = "x = 1 + 2\nprint(x)\n"
        findings = code_audit.scan(content, ArtifactType.SKILL, "safe.py")
        assert len(findings) == 0


# ===========================================================================
# 9. Backward compatibility: JS/TS files unchanged
# ===========================================================================


class TestBackwardCompatibilityJSTS:
    """Ensures .js/.ts file scanning behavior is unchanged."""

    def test_eval_in_js_still_detected(self, code_audit: CodeAuditScanner) -> None:
        """eval() in .js files is still caught."""
        content = "const result = eval(userInput);\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "plugin.js")
        assert any("eval" in f.evidence for f in findings)

    def test_insecure_http_in_js_still_detected(self, code_audit: CodeAuditScanner) -> None:
        """Insecure HTTP URLs in .js are still caught."""
        content = "const api = 'http://api.external.com/data';\n"
        findings = code_audit.scan(content, ArtifactType.PLUGIN, "plugin.js")
        assert any(f.id == "PL-S9" for f in findings)
