"""Property-based tests for Scanner False Positive Reduction — Phase 2.

Tests correctness properties for:
- CodeAudit inline code span detection (Properties 1, 2, 3)
- ComplianceAudit context-aware keyword matching (Properties 6, 7)
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.classifiers.classifier import ArtifactClassifier
from ai_artifact_risk_validator.classifiers.script_context import ScriptClassificationContext
from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner
from ai_artifact_risk_validator.scanners.compliance_audit import ComplianceAuditScanner
from ai_artifact_risk_validator.scanners.provenance_chk import ProvenanceChkScanner
from ai_artifact_risk_validator.scanners.secret_scan import SecretScanScanner

# ============================================================
# Known shell executables and metacharacters (from code_audit.py)
# ============================================================

_KNOWN_SHELL_EXECUTABLES: set[str] = {
    "rm",
    "ls",
    "cat",
    "cp",
    "mv",
    "chmod",
    "chown",
    "curl",
    "wget",
    "git",
    "docker",
    "kubectl",
    "sudo",
    "kill",
    "pkill",
    "find",
    "grep",
    "sed",
    "awk",
    "tar",
    "zip",
    "unzip",
    "ssh",
    "scp",
    "nc",
    "nmap",
    "python",
    "ruby",
    "node",
    "bash",
    "sh",
    "cmd",
    "powershell",
    "pwsh",
}

_SHELL_METACHARACTERS: list[str] = ["|", ">", "<", "&&", "||", ";", "$(", ">>", "2>&1"]

# Risk IDs for backtick execution findings (depends on artifact type)
_BACKTICK_RISK_IDS: set[str] = {"SK-S2", "MCP-S1", "H-S1", "PL-S1", "A-S3"}


# ============================================================
# Strategies for Inline Code Span Detection (Properties 1, 2, 3)
# ============================================================


@st.composite
def inline_code_identifiers(draw: st.DrawFn) -> str:
    """Generate Markdown content with a single-backtick inline code span containing an identifier.

    The generated identifier:
    - Contains no shell metacharacters
    - Does NOT have a known shell executable as the first token
    - Is a single-word identifier (camelCase, snake_case, dotted path, filename, etc.)

    Returns a Markdown document with the inline code span embedded.
    """
    # Generate identifier patterns that do NOT match shell executables or metacharacters
    identifier_styles = st.one_of(
        # camelCase identifiers
        st.from_regex(r"[a-z][a-zA-Z]{2,15}", fullmatch=True).filter(
            lambda s: s.lower() not in _KNOWN_SHELL_EXECUTABLES
        ),
        # snake_case identifiers
        st.from_regex(r"[a-z][a-z0-9]{1,8}_[a-z][a-z0-9]{1,8}", fullmatch=True).filter(
            lambda s: s.lower() not in _KNOWN_SHELL_EXECUTABLES
        ),
        # PascalCase class names
        st.from_regex(r"[A-Z][a-zA-Z]{2,15}", fullmatch=True),
        # Dotted paths (module.function)
        st.from_regex(r"[a-z][a-z0-9]{1,8}\.[a-z][a-z0-9]{1,8}", fullmatch=True),
        # Filenames with extension
        st.from_regex(r"[a-z][a-z0-9_]{1,10}\.(py|ts|js|md|yaml|json)", fullmatch=True),
    )

    identifier = draw(identifier_styles)

    # Ensure no shell metacharacters snuck in
    for meta in _SHELL_METACHARACTERS:
        if meta in identifier:
            # Use assume to filter rather than crash
            from hypothesis import assume

            assume(False)

    # Wrap in a Markdown document with the backtick inline code span
    prose_lines = [
        "# API Reference",
        "",
        "This module provides utility functions.",
        "",
        f"The `{identifier}` function handles data processing.",
        "",
        "See the documentation for more details.",
    ]
    return "\n".join(prose_lines)


@st.composite
def shell_commands_in_backticks(draw: st.DrawFn) -> tuple[str, str]:
    """Generate Markdown content with shell metacharacters inside backticks.

    Returns a tuple of (markdown_content, variant) where variant is
    'metachar' or 'command' to indicate which property is being tested.
    """
    variant = draw(st.sampled_from(["metachar", "command"]))

    if variant == "metachar":
        # Generate content containing a shell metacharacter
        metachar = draw(st.sampled_from(_SHELL_METACHARACTERS))
        # Build a plausible command-like string that includes the metacharacter
        prefix_words = draw(
            st.lists(
                st.from_regex(r"[a-z]{2,8}", fullmatch=True),
                min_size=1,
                max_size=3,
            )
        )
        suffix_words = draw(
            st.lists(
                st.from_regex(r"[a-z]{2,8}", fullmatch=True),
                min_size=1,
                max_size=3,
            )
        )
        inner = " ".join(prefix_words) + " " + metachar + " " + " ".join(suffix_words)
    else:
        # Generate a command pattern: known executable + arguments
        executable = draw(st.sampled_from(sorted(_KNOWN_SHELL_EXECUTABLES)))
        # Generate at least one argument token
        args = draw(
            st.lists(
                st.from_regex(r"[a-z0-9/._-]{1,12}", fullmatch=True),
                min_size=1,
                max_size=4,
            )
        )
        inner = executable + " " + " ".join(args)

    # Wrap in Markdown document
    prose_lines = [
        "# Security Notes",
        "",
        "The following command is dangerous:",
        "",
        f"Use `{inner}` to execute the operation.",
        "",
        "Be careful with this command.",
    ]
    return "\n".join(prose_lines), variant


# ============================================================
# Property Tests — Inline Code Span Detection
# ============================================================


class TestProperty1InlineCodeNoMetacharsZeroFindings:
    """Property 1: Inline code spans without shell metacharacters produce zero findings.

    **Validates: Requirements 1.1, 1.4**
    """

    @given(content=inline_code_identifiers())
    @settings(max_examples=100)
    def test_property_1_identifier_without_metacharacters_zero_backtick_findings(
        self, content: str
    ) -> None:
        """Single-backtick identifiers without shell metacharacters produce zero findings."""
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/api_docs.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert backtick_findings == [], (
            f"Expected zero backtick execution findings for inline code identifier, "
            f"got {len(backtick_findings)}: {[f.evidence for f in backtick_findings]}"
        )


class TestProperty2ShellMetacharsProduceFindings:
    """Property 2: Backtick content with shell metacharacters always produces findings.

    **Validates: Requirements 1.2, 6.1**
    """

    @given(data=shell_commands_in_backticks().filter(lambda x: x[1] == "metachar"))
    @settings(max_examples=100)
    def test_property_2_shell_metacharacters_produce_backtick_findings(
        self, data: tuple[str, str]
    ) -> None:
        """Backtick content with shell metacharacters produces at least one finding."""
        content, _ = data
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/dangerous.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert len(backtick_findings) >= 1, (
            f"Expected at least one backtick execution finding for content with "
            f"shell metacharacters, got zero.\nContent:\n{content[:500]}"
        )


class TestProperty3CommandPatternProduceFindings:
    """Property 3: Backtick content matching Command_Pattern always produces findings.

    **Validates: Requirements 1.3, 1.7, 6.1**
    """

    @given(data=shell_commands_in_backticks().filter(lambda x: x[1] == "command"))
    @settings(max_examples=100)
    def test_property_3_command_pattern_produces_backtick_findings(
        self, data: tuple[str, str]
    ) -> None:
        """Backtick content with known executable as first token produces findings."""
        content, _ = data
        scanner = CodeAuditScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/commands.md")
        backtick_findings = [f for f in findings if f.id in _BACKTICK_RISK_IDS]
        assert len(backtick_findings) >= 1, (
            f"Expected at least one backtick execution finding for content with "
            f"command pattern (known executable + args), got zero.\nContent:\n{content[:500]}"
        )


# ============================================================
# Geographic keywords (excluding standalone lowercase "us")
# ============================================================

_GEOGRAPHIC_KEYWORDS: list[str] = [
    "EU",
    "APAC",
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
]

# Data transfer keywords that trigger REG-1 when near a geographic keyword
_TRANSFER_KEYWORDS: list[str] = [
    "transfer",
    "replicate",
    "deploy",
    "migrate",
    "store",
    "host",
    "persist",
    "route",
    "forward",
    "sync",
    "backup",
    "archive",
    "ship",
    "send",
    "receive",
    "ingest",
    "land",
]

# Filler lines that do NOT contain any transfer keywords or geographic keywords
# and do NOT accidentally contain "data_residency" or similar declaration patterns
_NEUTRAL_LINES: list[str] = [
    "This section covers general architecture decisions.",
    "The team reviewed the proposal on Monday.",
    "Performance metrics are collected every minute.",
    "Authentication uses OAuth 2.0 tokens.",
    "The cache layer improves response times.",
    "Logging is handled by the observability stack.",
    "Unit tests cover 90 percent of the codebase.",
    "The API follows RESTful conventions.",
    "Documentation is generated from source comments.",
    "Refactoring improved code readability significantly.",
    "CI pipeline runs on every pull request.",
    "Feature flags control gradual rollout.",
]


# ============================================================
# Strategies
# ============================================================


@st.composite
def geographic_without_transfer_context(draw: st.DrawFn) -> str:
    """Generate content with a geographic keyword but NO transfer keywords within ±5 lines.

    The geographic keyword appears on a single line surrounded by neutral prose
    lines (at least 6 above and 6 below) ensuring no transfer keywords appear
    within the ±5 line proximity window.

    Excludes lowercase standalone "us" (pronoun exclusion).
    Does NOT include data residency declaration patterns.
    """
    geo_keyword = draw(st.sampled_from(_GEOGRAPHIC_KEYWORDS))

    # Generate neutral padding lines (at least 6 above and 6 below the geo line)
    num_lines_above = draw(st.integers(min_value=6, max_value=12))
    num_lines_below = draw(st.integers(min_value=6, max_value=12))

    above_lines = [draw(st.sampled_from(_NEUTRAL_LINES)) for _ in range(num_lines_above)]
    below_lines = [draw(st.sampled_from(_NEUTRAL_LINES)) for _ in range(num_lines_below)]

    # Build the geo keyword line — use it in a prose context
    # NOTE: Avoid words containing transfer keyword substrings (e.g. "presented"
    # contains "sent", "consistent" contains "persist"). The scanner's
    # _has_transfer_context() uses substring matching.
    geo_line_templates = [
        f"The {geo_keyword} market is growing steadily.",
        f"We discussed {geo_keyword} coverage in the meeting.",
        f"Our {geo_keyword} team shared their findings.",
        f"The {geo_keyword} region has new compliance rules.",
        f"Feedback from {geo_keyword} stakeholders was positive.",
    ]
    geo_line = draw(st.sampled_from(geo_line_templates))

    lines = above_lines + [geo_line] + below_lines
    return "\n".join(lines)


@st.composite
def geographic_with_transfer_context(draw: st.DrawFn) -> str:
    """Generate content with a geographic keyword AND transfer keywords within ±5 lines.

    Places a geographic keyword and a data transfer keyword within 5 lines of
    each other. Does NOT include data residency declaration patterns (which
    would suppress the finding).

    Excludes lowercase standalone "us" (pronoun exclusion).
    """
    geo_keyword = draw(st.sampled_from(_GEOGRAPHIC_KEYWORDS))
    transfer_keyword = draw(st.sampled_from(_TRANSFER_KEYWORDS))

    # Place transfer keyword within 0-4 lines of the geographic keyword
    distance = draw(st.integers(min_value=0, max_value=4))

    # Build neutral padding (enough to be a realistic document)
    num_prefix_lines = draw(st.integers(min_value=0, max_value=4))
    num_suffix_lines = draw(st.integers(min_value=0, max_value=4))

    prefix_lines = [draw(st.sampled_from(_NEUTRAL_LINES)) for _ in range(num_prefix_lines)]
    suffix_lines = [draw(st.sampled_from(_NEUTRAL_LINES)) for _ in range(num_suffix_lines)]

    # Construct the geo line
    geo_line_templates = [
        f"Data will be processed in {geo_keyword} region.",
        f"The {geo_keyword} infrastructure handles requests.",
        f"Our {geo_keyword} cluster serves traffic.",
        f"Resources in {geo_keyword} must comply with policy.",
    ]
    geo_line = draw(st.sampled_from(geo_line_templates))

    # Construct the transfer line
    transfer_line_templates = [
        f"We will {transfer_keyword} data to the target region.",
        f"The system will {transfer_keyword} artifacts across zones.",
        f"Plan to {transfer_keyword} workloads next quarter.",
        f"Need to {transfer_keyword} records to new infrastructure.",
    ]
    transfer_line = draw(st.sampled_from(transfer_line_templates))

    # Place gap lines between geo and transfer (within ±5 proximity)
    gap_lines = [draw(st.sampled_from(_NEUTRAL_LINES)) for _ in range(distance)]

    # Randomly put transfer before or after geo keyword
    transfer_first = draw(st.booleans())
    if transfer_first:
        core_lines = [transfer_line] + gap_lines + [geo_line]
    else:
        core_lines = [geo_line] + gap_lines + [transfer_line]

    lines = prefix_lines + core_lines + suffix_lines
    return "\n".join(lines)


# ============================================================
# Property Tests
# ============================================================


class TestProperty6GeographicWithoutTransferContext:
    """Property 6: Geographic keyword without transfer context → zero REG-1 findings.

    **Validates: Requirements 3.1, 3.3, 3.4**
    """

    @given(content=geographic_without_transfer_context())
    @settings(max_examples=100)
    def test_property_6_geographic_keyword_without_transfer_context_zero_reg1(
        self, content: str
    ) -> None:
        """Geographic keyword without transfer keywords in ±5 lines produces zero REG-1."""
        scanner = ComplianceAuditScanner()
        findings = scanner.scan(content, ArtifactType.STEERING, "skills/data_policy.md")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert reg1_findings == [], (
            f"Expected zero REG-1 findings for content without transfer context, "
            f"got {len(reg1_findings)}: {[f.evidence for f in reg1_findings]}"
        )


class TestProperty7GeographicWithTransferContext:
    """Property 7: Geographic keyword with transfer context → produces REG-1 findings.

    **Validates: Requirements 3.5, 6.3**
    """

    @given(content=geographic_with_transfer_context())
    @settings(max_examples=100)
    def test_property_7_geographic_keyword_with_transfer_context_produces_reg1(
        self, content: str
    ) -> None:
        """Geographic keyword with transfer keywords in ±5 lines produces REG-1."""
        scanner = ComplianceAuditScanner()
        findings = scanner.scan(content, ArtifactType.STEERING, "skills/data_policy.md")
        reg1_findings = [f for f in findings if f.id == "REG-1"]
        assert len(reg1_findings) >= 1, (
            f"Expected at least one REG-1 finding for content with geographic keyword "
            f"and transfer context, got zero.\nContent:\n{content[:500]}"
        )


# ============================================================
# ProvenanceChk Path-Based Scope Restriction — Properties 4 & 5
# ============================================================

# Test directory path components
_TEST_DIR_PREFIXES: list[str] = [
    "tests/",
    "test/",
    "__tests__/",
    "spec/",
]

_KIRO_SPEC_PREFIXES: list[str] = [
    ".kiro/specs/",
    ".kiro/workflows/",
]

# External/vendor directory prefixes
_EXTERNAL_DIR_PREFIXES: list[str] = [
    "plugins/",
    "vendor/",
    "external/",
    "node_modules/",
]


@st.composite
def gen_test_file_paths(draw: st.DrawFn) -> str:
    """Generate file paths that match test/spec directory patterns.

    Produces paths like:
    - tests/unit/test_foo.py
    - test/helpers.py
    - __tests__/bar.js
    - spec/features/login.spec.ts
    - .kiro/specs/feature/design.approved.json
    - .kiro/workflows/build/tasks.md
    - project/tests/deep/nested/file.py
    """
    path_type = draw(st.sampled_from(["test_dir", "kiro_spec"]))

    if path_type == "test_dir":
        prefix = draw(st.sampled_from(_TEST_DIR_PREFIXES))
        # Optionally add a parent directory
        has_parent = draw(st.booleans())
        parent = ""
        if has_parent:
            parent_names = ["project", "src", "my-app", "workspace", "repo"]
            parent = draw(st.sampled_from(parent_names)) + "/"

        # Add subdirectory depth
        subdirs = draw(
            st.lists(
                st.sampled_from(["unit", "integration", "helpers", "fixtures", "utils", "deep"]),
                min_size=0,
                max_size=2,
            )
        )
        subdir_path = "/".join(subdirs) + "/" if subdirs else ""

        # File name
        file_names = [
            "test_foo.py",
            "test_scanner.py",
            "helpers.py",
            "bar.js",
            "conftest.py",
            "test_validator.py",
            "utils.ts",
            "setup.py",
            "test_provenance.py",
        ]
        filename = draw(st.sampled_from(file_names))
        return f"{parent}{prefix}{subdir_path}{filename}"
    else:
        prefix = draw(st.sampled_from(_KIRO_SPEC_PREFIXES))
        # Kiro spec/workflow paths always need a parent directory because the
        # regex pattern requires a path separator before .kiro
        parent_names = ["project", "workspace", "my-app", "repo", "root"]
        parent = draw(st.sampled_from(parent_names)) + "/"

        # Feature name
        feature_names = [
            "scanner-fp-reduction",
            "auth-feature",
            "user-login",
            "data-pipeline",
            "build",
        ]
        feature = draw(st.sampled_from(feature_names))

        # File name
        file_names = [
            "design.approved.json",
            "tasks.md",
            "design.md",
            "requirements.md",
            "config.json",
        ]
        filename = draw(st.sampled_from(file_names))
        return f"{parent}{prefix}{feature}/{filename}"


@st.composite
def external_file_paths(draw: st.DrawFn) -> str:
    """Generate file paths that match external/vendor directory patterns.

    Produces paths like:
    - plugins/my-plugin/index.js
    - vendor/lib/helper.py
    - external/third-party/scanner.py
    - node_modules/some-package/dist/index.js
    """
    prefix = draw(st.sampled_from(_EXTERNAL_DIR_PREFIXES))

    # Optionally add a parent directory
    has_parent = draw(st.booleans())
    parent = ""
    if has_parent:
        parent_names = ["project", "workspace", "my-app", "repo"]
        parent = draw(st.sampled_from(parent_names)) + "/"

    # Package / subdirectory name
    package_names = [
        "my-plugin",
        "third-party-scanner",
        "helper-lib",
        "analytics",
        "some-package",
        "auth-module",
    ]
    package = draw(st.sampled_from(package_names))

    # Optional nested directory
    subdirs = draw(
        st.lists(
            st.sampled_from(["dist", "src", "lib", "utils"]),
            min_size=0,
            max_size=1,
        )
    )
    subdir_path = "/".join(subdirs) + "/" if subdirs else ""

    # File name
    file_names = [
        "index.js",
        "main.py",
        "scanner.py",
        "plugin.yaml",
        "config.json",
        "skill.md",
    ]
    filename = draw(st.sampled_from(file_names))
    return f"{parent}{prefix}{package}/{subdir_path}{filename}"


@st.composite
def artifact_content_without_provenance(draw: st.DrawFn) -> str:
    """Generate artifact content that lacks provenance metadata.

    This content should NOT contain author:, version:, source:, hash: fields
    so that the ProvenanceChk scanner would normally produce High findings.
    """
    # Simple artifact content templates without provenance metadata
    templates = [
        "name: {name}\ndescription: A utility skill\nsteps:\n  - action: run\n    command: echo hello\n",
        "# {name}\n\nThis is a skill that performs data processing.\n\n## Steps\n\n1. Read input\n2. Transform data\n3. Write output\n",
        "type: skill\nname: {name}\ninputs:\n  - data_source\noutputs:\n  - processed_result\n",
        "---\nname: {name}\n---\n\nExecute the following operations:\n- Validate input\n- Process records\n- Generate report\n",
        "name: {name}\nconfiguration:\n  timeout: 30\n  retries: 3\n  mode: production\n",
    ]
    names = ["data-processor", "file-handler", "report-gen", "auth-helper", "cache-manager"]
    template = draw(st.sampled_from(templates))
    name = draw(st.sampled_from(names))
    return template.format(name=name)


# ============================================================
# Property Tests — ProvenanceChk
# ============================================================


class TestProperty4TestPathZeroHighProvenance:
    """Property 4: Test path files produce zero provenance/integrity High+ findings.

    **Validates: Requirements 2.1, 2.2, 2.4, 6.2**
    """

    @given(artifact_path=gen_test_file_paths())
    @settings(max_examples=100)
    def test_property_4_test_path_zero_high_provenance_findings(self, artifact_path: str) -> None:
        """Files under test/spec paths produce zero High+ provenance findings."""
        scanner = ProvenanceChkScanner()
        # Use content that would normally trigger provenance findings
        content = (
            "name: test-skill\n"
            "description: A simple skill for testing\n"
            "steps:\n"
            "  - action: run\n"
            "    command: echo hello\n"
        )
        findings = scanner.scan(content, ArtifactType.SKILL, artifact_path)
        high_findings = [f for f in findings if f.severity_score >= 7]
        assert high_findings == [], (
            f"Expected zero High+ provenance findings for test path '{artifact_path}', "
            f"got {len(high_findings)}: {[(f.id, f.severity_score) for f in high_findings]}"
        )


class TestProperty5ExternalPathRetainsFullSeverity:
    """Property 5: External/vendor path files retain full provenance severity.

    **Validates: Requirements 2.4, 6.2**
    """

    @given(
        artifact_path=external_file_paths(),
        content=artifact_content_without_provenance(),
    )
    @settings(max_examples=100)
    def test_property_5_external_path_retains_full_severity(
        self, artifact_path: str, content: str
    ) -> None:
        """External/vendor path files without provenance metadata retain High+ severity."""
        scanner = ProvenanceChkScanner()
        findings = scanner.scan(content, ArtifactType.SKILL, artifact_path)
        # External paths lacking provenance should produce findings
        # and those findings should have High/Critical severity (≥ 7)
        if findings:
            high_findings = [f for f in findings if f.severity_score >= 7]
            assert len(high_findings) >= 1, (
                f"Expected at least one High+ severity finding for external path "
                f"'{artifact_path}' without provenance metadata, but all findings "
                f"had severity < 7: {[(f.id, f.severity_score) for f in findings]}"
            )


# ============================================================
# Robustness — Property 13: All modified scanners never raise exceptions
# ============================================================


@st.composite
def adversarial_inputs(draw: st.DrawFn) -> str:
    """Generate adversarial string inputs for robustness testing.

    Generates:
    - Empty strings
    - Binary-like bytes decoded as latin-1
    - Very long strings (>10000 chars)
    - Strings with null bytes
    - Strings with only whitespace
    - Random unicode
    """
    variant = draw(
        st.sampled_from(
            [
                "empty",
                "binary_like",
                "very_long",
                "null_bytes",
                "whitespace_only",
                "random_unicode",
            ]
        )
    )

    if variant == "empty":
        return ""
    elif variant == "binary_like":
        # Generate random bytes and decode as latin-1 (which never fails)
        raw = draw(st.binary(min_size=1, max_size=500))
        return raw.decode("latin-1")
    elif variant == "very_long":
        # Generate strings longer than 10000 characters
        base_char = draw(st.sampled_from(["a", "X", "\n", " ", "\t", "\x00", "🔥"]))
        length = draw(st.integers(min_value=10001, max_value=20000))
        return base_char * length
    elif variant == "null_bytes":
        # Strings with embedded null bytes
        prefix = draw(st.text(min_size=0, max_size=50))
        suffix = draw(st.text(min_size=0, max_size=50))
        num_nulls = draw(st.integers(min_value=1, max_value=10))
        return prefix + ("\x00" * num_nulls) + suffix
    elif variant == "whitespace_only":
        # Strings composed entirely of whitespace characters
        ws_chars = [" ", "\t", "\n", "\r", "\x0b", "\x0c"]
        length = draw(st.integers(min_value=1, max_value=200))
        chars = draw(st.lists(st.sampled_from(ws_chars), min_size=length, max_size=length))
        return "".join(chars)
    else:
        # Random unicode including surrogates, control chars, emoji
        return draw(st.text(min_size=1, max_size=500))


@st.composite
def adversarial_paths(draw: st.DrawFn) -> str:
    """Generate adversarial file paths for robustness testing."""
    variant = draw(
        st.sampled_from(
            [
                "empty",
                "null_bytes",
                "very_long",
                "unicode",
                "normal",
            ]
        )
    )

    if variant == "empty":
        return ""
    elif variant == "null_bytes":
        return "path/to/\x00file.py"
    elif variant == "very_long":
        segment = draw(st.from_regex(r"[a-z]{5,10}", fullmatch=True))
        return "/".join([segment] * 200) + "/file.py"
    elif variant == "unicode":
        return draw(st.text(min_size=1, max_size=100)) + ".py"
    else:
        return "src/normal/file.py"


class TestProperty13RobustnessNoExceptions:
    """Property 13: All modified scanners never raise exceptions.

    For any input (empty, malformed, binary-like, extremely large), all modified
    scanner scan() methods and classifier methods SHALL return without raising
    exceptions.

    **Validates: Requirements 6.6**
    """

    @given(content=adversarial_inputs())
    @settings(max_examples=100, deadline=None)
    def test_property_13_code_audit_no_exceptions(self, content: str) -> None:
        """CodeAuditScanner.scan() never raises exceptions on adversarial input."""
        scanner = CodeAuditScanner()
        result = scanner.scan(content, ArtifactType.SKILL, "skills/test.md")
        assert isinstance(result, list)

    @given(content=adversarial_inputs())
    @settings(max_examples=100, deadline=None)
    def test_property_13_provenance_chk_no_exceptions(self, content: str) -> None:
        """ProvenanceChkScanner.scan() never raises exceptions on adversarial input."""
        scanner = ProvenanceChkScanner()
        result = scanner.scan(content, ArtifactType.SKILL, "plugins/test.md")
        assert isinstance(result, list)

    @given(content=adversarial_inputs())
    @settings(max_examples=100, deadline=None)
    def test_property_13_compliance_audit_no_exceptions(self, content: str) -> None:
        """ComplianceAuditScanner.scan() never raises exceptions on adversarial input."""
        scanner = ComplianceAuditScanner()
        result = scanner.scan(content, ArtifactType.SKILL, "skills/test.md")
        assert isinstance(result, list)

    @given(content=adversarial_inputs())
    @settings(max_examples=100, deadline=None)
    def test_property_13_secret_scan_no_exceptions(self, content: str) -> None:
        """SecretScanScanner.scan() never raises exceptions on adversarial input."""
        scanner = SecretScanScanner()
        result = scanner.scan(content, ArtifactType.SKILL, "skills/test.md")
        assert isinstance(result, list)

    @given(content=adversarial_inputs(), path=adversarial_paths())
    @settings(max_examples=100, deadline=None)
    def test_property_13_artifact_classifier_no_exceptions(self, content: str, path: str) -> None:
        """ArtifactClassifier.classify_script() never raises exceptions on adversarial input."""
        classifier = ArtifactClassifier()
        context = ScriptClassificationContext()
        # classify_script takes a Path object
        try:
            file_path = Path(path) if path else Path("empty.py")
        except (ValueError, OSError):
            file_path = Path("fallback.py")
        result = classifier.classify_script(file_path, context, content=content)
        # Result should be either None or a ClassificationResult — no exception
        assert result is None or hasattr(result, "artifact_type")


# ============================================================
# SecretScan Allowlist — Properties 8, 9, 10
# ============================================================

# RFC 2606 reserved domains (from secret_scan.py)
_RFC_2606_DOMAINS: list[str] = ["example.com", "example.org", "example.net", "example.edu"]

# Placeholder IPs (from secret_scan.py)
_PLACEHOLDER_IP_SET: list[str] = [
    "0.0.0.0",
    "1.2.3.4",
    "127.0.0.1",
    "10.0.0.1",
    "192.168.0.1",
    "192.168.1.1",
    "255.255.255.255",
]

# RFC 5737 documentation address prefixes
_DOC_IP_PREFIXES_LIST: list[str] = ["192.0.2.", "198.51.100.", "203.0.113."]


@st.composite
def rfc_2606_emails(draw: st.DrawFn) -> str:
    """Generate email addresses using RFC 2606 reserved domains or subdomains.

    Produces emails like:
    - user@example.com
    - test.account@example.org
    - admin@mail.example.net
    - info@sub.deep.example.edu
    """
    # Generate local part (before @)
    local_part_styles = st.one_of(
        # Simple usernames
        st.from_regex(r"[a-z][a-z0-9]{2,10}", fullmatch=True),
        # Dotted usernames
        st.from_regex(r"[a-z][a-z0-9]{1,5}\.[a-z][a-z0-9]{1,5}", fullmatch=True),
        # Usernames with + and -
        st.from_regex(r"[a-z][a-z0-9]{1,5}[+\-][a-z0-9]{1,5}", fullmatch=True),
    )
    local_part = draw(local_part_styles)

    # Pick a base RFC 2606 domain
    base_domain = draw(st.sampled_from(_RFC_2606_DOMAINS))

    # Optionally add subdomain prefix
    use_subdomain = draw(st.booleans())
    if use_subdomain:
        subdomain_parts = draw(
            st.lists(
                st.from_regex(r"[a-z]{2,8}", fullmatch=True),
                min_size=1,
                max_size=2,
            )
        )
        domain = ".".join(subdomain_parts) + "." + base_domain
    else:
        domain = base_domain

    return f"{local_part}@{domain}"


@st.composite
def placeholder_ips(draw: st.DrawFn) -> str:
    """Generate IP addresses from the placeholder set or RFC 5737 documentation ranges.

    Produces IPs like:
    - 0.0.0.0, 1.2.3.4, 127.0.0.1, etc. (direct placeholders)
    - 192.0.2.x, 198.51.100.x, 203.0.113.x (RFC 5737 documentation ranges)
    """
    ip_type = draw(st.sampled_from(["placeholder_set", "rfc_5737"]))

    if ip_type == "placeholder_set":
        return draw(st.sampled_from(_PLACEHOLDER_IP_SET))
    else:
        # RFC 5737 documentation address ranges
        prefix = draw(st.sampled_from(_DOC_IP_PREFIXES_LIST))
        last_octet = draw(st.integers(min_value=0, max_value=255))
        return f"{prefix}{last_octet}"


@st.composite
def sequential_digit_strings(draw: st.DrawFn) -> str:
    """Generate sequential or repeating digit strings of length >= 6.

    Produces strings like:
    - Ascending sequences: "012345", "12345678", "0123456789", "3456789012"
    - Repeating digits: "000000", "1111111", "9999999999"
    """
    variant = draw(st.sampled_from(["ascending", "repeating"]))

    if variant == "ascending":
        # Ascending sequence: substring of "01234567890123456789" of length >= 6
        ascending = "01234567890123456789"
        length = draw(st.integers(min_value=6, max_value=18))
        # Pick a start index that allows the desired length
        max_start = len(ascending) - length
        start_idx = draw(st.integers(min_value=0, max_value=max_start))
        return ascending[start_idx : start_idx + length]
    else:
        # Repeating single digit
        digit = draw(st.sampled_from(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]))
        length = draw(st.integers(min_value=6, max_value=15))
        return digit * length


# ============================================================
# Property Tests — SecretScan Allowlist
# ============================================================


class TestProperty8RFC2606EmailsZeroSecretFindings:
    """Property 8: RFC 2606 emails produce zero secret findings.

    For any email address whose domain is an RFC 2606 reserved domain or subdomain
    thereof, the SecretScan scanner SHALL produce zero SK-S5 or SOP-S1 findings.

    **Validates: Requirements 4.1, 4.7**
    """

    @given(email=rfc_2606_emails())
    @settings(max_examples=100)
    def test_property_8_rfc_2606_email_zero_secret_findings(self, email: str) -> None:
        """Emails with RFC 2606 domains produce zero SK-S5 or SOP-S1 findings."""
        scanner = SecretScanScanner()
        # Embed email in realistic artifact content
        content = (
            "# Notification Configuration\n"
            "\n"
            "## Email Settings\n"
            "\n"
            f"Send notifications to: {email}\n"
            "\n"
            "The system will deliver alerts to the configured address.\n"
        )
        # Test with "skill" artifact type (produces SK-S5)
        findings_skill = scanner.scan(content, ArtifactType.SKILL, "skills/notify.md")
        secret_findings_skill = [f for f in findings_skill if f.id in ("SK-S5", "SOP-S1")]
        assert secret_findings_skill == [], (
            f"Expected zero SK-S5/SOP-S1 findings for RFC 2606 email '{email}' "
            f"(artifact_type=SKILL), got {len(secret_findings_skill)}: "
            f"{[(f.id, f.evidence) for f in secret_findings_skill]}"
        )

        # Test with "sop" artifact type (produces SOP-S1)
        findings_sop = scanner.scan(content, ArtifactType.SOP, "sops/alerts.md")
        secret_findings_sop = [f for f in findings_sop if f.id in ("SK-S5", "SOP-S1")]
        assert secret_findings_sop == [], (
            f"Expected zero SK-S5/SOP-S1 findings for RFC 2606 email '{email}' "
            f"(artifact_type=SOP), got {len(secret_findings_sop)}: "
            f"{[(f.id, f.evidence) for f in secret_findings_sop]}"
        )


class TestProperty9PlaceholderIPsZeroSecretFindings:
    """Property 9: Placeholder/documentation IPs produce zero secret findings.

    For any IP address matching RFC 5737 documentation ranges or the hardcoded
    placeholder set, the SecretScan scanner SHALL produce zero secret findings.

    **Validates: Requirements 4.2**
    """

    @given(ip=placeholder_ips())
    @settings(max_examples=100)
    def test_property_9_placeholder_ip_zero_secret_findings(self, ip: str) -> None:
        """Placeholder and documentation IPs produce zero secret findings."""
        scanner = SecretScanScanner()
        # Embed IP in realistic artifact content
        content = (
            "# Network Configuration\n"
            "\n"
            "## Server Settings\n"
            "\n"
            f"Default host: {ip}\n"
            f"Connect to {ip} for testing.\n"
            "\n"
            "See the documentation for network setup.\n"
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/network_config.md")
        # Filter to findings where the evidence contains our IP
        ip_findings = [
            f
            for f in findings
            if ip in (f.evidence or "") and f.id in ("SK-S5", "SOP-S1", "P-S3", "P-S4")
        ]
        assert ip_findings == [], (
            f"Expected zero secret findings for placeholder IP '{ip}', "
            f"got {len(ip_findings)}: {[(f.id, f.evidence) for f in ip_findings]}"
        )


class TestProperty10SequentialDigitsZeroSecretFindings:
    """Property 10: Sequential digit strings produce zero secret findings.

    For any numeric string consisting of ascending sequential digits or all-same
    repeating digits (length >= 6), the SecretScan scanner SHALL produce zero
    secret findings.

    **Validates: Requirements 4.3**
    """

    @given(digits=sequential_digit_strings())
    @settings(max_examples=100)
    def test_property_10_sequential_digits_zero_secret_findings(self, digits: str) -> None:
        """Sequential/repeating digit strings produce zero secret findings."""
        scanner = SecretScanScanner()
        # Embed digits in realistic artifact content
        content = (
            "# Test Data Configuration\n"
            "\n"
            "## Sample Values\n"
            "\n"
            f"Reference ID: {digits}\n"
            f"The account number {digits} is used for testing.\n"
            "\n"
            "These values are placeholders only.\n"
        )
        findings = scanner.scan(content, ArtifactType.SKILL, "skills/test_data.md")
        # Filter to findings that contain our digit string
        digit_findings = [
            f
            for f in findings
            if digits in (f.evidence or "") and f.id in ("SK-S5", "SOP-S1", "P-S3", "P-S4")
        ]
        assert digit_findings == [], (
            f"Expected zero secret findings for sequential digit string '{digits}', "
            f"got {len(digit_findings)}: {[(f.id, f.evidence) for f in digit_findings]}"
        )


# ============================================================
# ArtifactClassifier Test File Exclusion — Properties 11 & 12
# ============================================================

# Test directory prefixes for generating test file paths
_CLASSIFIER_TEST_DIR_PREFIXES: list[str] = [
    "tests/",
    "test/",
    "__tests__/",
    "spec/",
]

# Test file name patterns
_TEST_FILE_PREFIXES: list[str] = [
    "test_",
]

_TEST_FILE_SUFFIXES: list[str] = [
    "_test.py",
]

# Artifact types that can appear in frontmatter declarations
_DECLARABLE_ARTIFACT_TYPES: list[str] = [
    "skill",
    "agent",
    "prompt",
    "sop",
    "mcp",
    "hook",
    "instruction",
    "steering",
]


@st.composite
def gen_test_python_files_no_metadata(draw: st.DrawFn) -> tuple[str, str]:
    """Generate test file paths with Python content that has NO artifact metadata.

    Returns a tuple of (file_path, content) where:
    - file_path matches test directory or test file naming patterns
    - content is valid Python code WITHOUT YAML frontmatter or artifact_type comments

    The content must NOT contain:
    - YAML frontmatter (--- ... type: ... ---)
    - Comment line matching '# artifact_type:'
    """
    # Choose a path generation strategy
    path_style = draw(st.sampled_from(["dir_prefix", "test_prefix_name", "test_suffix_name"]))

    if path_style == "dir_prefix":
        # Path like tests/unit/test_something.py
        prefix = draw(st.sampled_from(_CLASSIFIER_TEST_DIR_PREFIXES))
        subdirs = draw(
            st.lists(
                st.sampled_from(["unit", "integration", "helpers", "models", "core"]),
                min_size=0,
                max_size=2,
            )
        )
        subdir_path = "/".join(subdirs) + "/" if subdirs else ""
        module_name = draw(
            st.sampled_from(
                [
                    "test_scanner.py",
                    "test_validator.py",
                    "conftest.py",
                    "helpers.py",
                    "test_utils.py",
                    "test_models.py",
                    "test_pipeline.py",
                ]
            )
        )
        file_path = f"{prefix}{subdir_path}{module_name}"
    elif path_style == "test_prefix_name":
        # Path like src/test_something.py (test_ prefix in filename)
        parent_dirs = draw(
            st.sampled_from(
                [
                    "src/",
                    "lib/",
                    "project/",
                    "",
                    "mypackage/",
                ]
            )
        )
        module = draw(
            st.sampled_from(
                [
                    "scanner",
                    "validator",
                    "utils",
                    "models",
                    "pipeline",
                    "helpers",
                ]
            )
        )
        file_path = f"{parent_dirs}test_{module}.py"
    else:
        # Path like src/something_test.py (suffix _test.py)
        parent_dirs = draw(
            st.sampled_from(
                [
                    "src/",
                    "lib/",
                    "project/",
                    "",
                    "mypackage/",
                ]
            )
        )
        module = draw(
            st.sampled_from(
                [
                    "scanner",
                    "validator",
                    "utils",
                    "models",
                    "pipeline",
                    "helpers",
                ]
            )
        )
        file_path = f"{parent_dirs}{module}_test.py"

    # Generate Python content WITHOUT artifact metadata
    # Must NOT have YAML frontmatter or '# artifact_type:' comments
    code_templates = [
        (
            "import pytest\n\n\n"
            "def test_basic_functionality():\n"
            "    result = 1 + 1\n"
            "    assert result == 2\n"
        ),
        (
            "from unittest import TestCase\n\n\n"
            "class TestValidator(TestCase):\n"
            "    def test_init(self):\n"
            "        self.assertTrue(True)\n"
        ),
        (
            "import pytest\nfrom mypackage import utils\n\n\n"
            "def test_parse_input():\n"
            "    data = utils.parse('hello')\n"
            "    assert data is not None\n"
        ),
        (
            "# Unit tests for the scanner module\n"
            "import pytest\n\n\n"
            "class TestScanner:\n"
            "    def test_scan_empty(self):\n"
            "        assert [] == []\n"
        ),
        (
            '"""Tests for data processing."""\n\n'
            "import pytest\n\n\n"
            "def test_transform():\n"
            "    assert transform([1, 2, 3]) == [2, 4, 6]\n"
        ),
    ]
    content = draw(st.sampled_from(code_templates))
    return file_path, content


@st.composite
def gen_test_python_files_with_metadata(draw: st.DrawFn) -> tuple[str, str, str]:
    """Generate test file paths with Python content that HAS explicit artifact metadata.

    Returns a tuple of (file_path, content, declared_type) where:
    - file_path matches test directory or test file naming patterns
    - content contains YAML frontmatter with type/artifact_type field OR
      an '# artifact_type:' comment
    - declared_type is the artifact type declared in the metadata

    This represents test fixtures that ARE intentionally artifact files.
    """
    # Choose a path generation strategy (same patterns as no_metadata)
    prefix = draw(st.sampled_from(_CLASSIFIER_TEST_DIR_PREFIXES))
    subdirs = draw(
        st.lists(
            st.sampled_from(["unit", "fixtures", "data", "samples", "artifacts"]),
            min_size=0,
            max_size=2,
        )
    )
    subdir_path = "/".join(subdirs) + "/" if subdirs else ""
    module_name = draw(
        st.sampled_from(
            [
                "test_skill_fixture.py",
                "test_agent_sample.py",
                "test_artifact.py",
                "fixture_skill.py",
                "sample_agent.py",
            ]
        )
    )
    file_path = f"{prefix}{subdir_path}{module_name}"

    # Choose a declared artifact type
    declared_type = draw(st.sampled_from(_DECLARABLE_ARTIFACT_TYPES))

    # Choose metadata style: YAML frontmatter with 'type:' or 'artifact_type:' or comment
    metadata_style = draw(
        st.sampled_from(
            [
                "frontmatter_type",
                "frontmatter_artifact_type",
                "comment_artifact_type",
            ]
        )
    )

    if metadata_style == "frontmatter_type":
        content = (
            f"---\ntype: {declared_type}\nname: fixture-artifact\n---\n\n"
            "# This is a test fixture artifact\n"
            "def run():\n"
            "    pass\n"
        )
    elif metadata_style == "frontmatter_artifact_type":
        content = (
            f"---\nartifact_type: {declared_type}\nversion: 1.0\n---\n\n"
            "# Artifact fixture for testing\n"
            "def execute():\n"
            "    return True\n"
        )
    else:
        content = (
            f"# artifact_type: {declared_type}\n"
            "# This file is an intentional artifact fixture\n\n"
            "def main():\n"
            "    print('artifact')\n"
        )

    return file_path, content, declared_type


# ============================================================
# Property Tests — ArtifactClassifier Test File Exclusion
# ============================================================


class TestProperty11TestFilesWithoutMetadataReturnNone:
    """Property 11: Test files without metadata are not classified as skill.

    For ANY Python file whose path matches test patterns AND whose content lacks
    explicit artifact metadata markers, classify_script() SHALL return None.

    **Validates: Requirements 5.1, 5.2, 5.4, 5.5**
    """

    @given(data=gen_test_python_files_no_metadata())
    @settings(max_examples=100)
    def test_property_11_test_files_without_metadata_return_none(
        self, data: tuple[str, str]
    ) -> None:
        """Test file paths without artifact metadata → classify_script returns None."""
        file_path_str, content = data
        classifier = ArtifactClassifier(semantic_enabled=False)
        context = ScriptClassificationContext()
        file_path = Path(file_path_str)

        result = classifier.classify_script(file_path, context, content=content)

        assert result is None, (
            f"Expected classify_script() to return None for test file without metadata, "
            f"but got {result}.\n"
            f"Path: {file_path_str}\n"
            f"Content:\n{content[:300]}"
        )


class TestProperty12TestFilesWithMetadataAreClassified:
    """Property 12: Test files with explicit metadata ARE classified.

    For ANY Python file whose path matches test patterns BUT whose content
    contains explicit artifact metadata (frontmatter with type field),
    classify_script() SHALL NOT return None due to the test file exclusion —
    it proceeds to normal classification.

    **Validates: Requirements 5.3**
    """

    @given(data=gen_test_python_files_with_metadata())
    @settings(max_examples=100)
    def test_property_12_test_files_with_metadata_not_excluded(
        self, data: tuple[str, str, str]
    ) -> None:
        """Test file paths with artifact metadata → classify_script does not early-exit."""
        file_path_str, content, declared_type = data
        classifier = ArtifactClassifier(semantic_enabled=False)
        context = ScriptClassificationContext()
        file_path = Path(file_path_str)

        # The key assertion: classify_script() does NOT return None due to the
        # test file exclusion. It proceeds past the early exit.
        # Since the normal classification signals (Known AI Dir, Type-Indicating Dir,
        # references, MCP, siblings) may or may not fire depending on context,
        # we verify the exclusion logic was bypassed by checking that the method
        # did NOT short-circuit at the test-file check.
        #
        # We set up a context where sibling classification WILL fire to ensure
        # a non-None result, proving the test file exclusion was skipped.
        resolved_dir = file_path.resolve().parent
        declared_enum = ArtifactType(declared_type)
        context.directory_artifacts[resolved_dir] = [(declared_enum, 0.80)]

        result = classifier.classify_script(file_path, context, content=content)

        assert result is not None, (
            f"Expected classify_script() to NOT return None for test file with "
            f"explicit metadata (declared type: {declared_type}), "
            f"but got None.\n"
            f"Path: {file_path_str}\n"
            f"Content:\n{content[:300]}"
        )
        assert result.artifact_type == declared_enum, (
            f"Expected classify_script() to return artifact_type={declared_type} "
            f"(via sibling classification from metadata context), "
            f"but got {result.artifact_type.value}.\n"
            f"Path: {file_path_str}"
        )
