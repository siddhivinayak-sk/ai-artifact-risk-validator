"""Property-based tests for SQL injection detection in Java/Kotlin.

**Property 5: SQL Injection Detection Across Languages (Java subset)**
**Validates: Requirements 3.4, 3.7**

For any Java/Kotlin source containing string concatenation in SQL statements
(non-parameterized queries) or JNDI lookups with dynamic names, the JavaAnalyzer
SHALL produce at least one ScanFinding with id="MCP-S6".
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.java_analyzer import JavaAnalyzer

# --- Strategies ---

# Valid Java variable names (identifiers)
_identifier_strategy = st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,15}", fullmatch=True)

# Random safe Java code lines used as padding
_safe_code_line = st.sampled_from(
    [
        "int x = 1;",
        'String result = "";',
        "List<String> items = new ArrayList<>();",
        'logger.info("processing request");',
        "import java.util.List;",
        "public class MyService {",
        "// TODO: refactor this",
        "return Optional.empty();",
        "if (condition) { doStuff(); }",
        "private final DataSource dataSource;",
    ]
)

# Generate random padding (prefix and suffix lines)
_padding_strategy = st.lists(_safe_code_line, min_size=0, max_size=5).map(
    lambda lines: "\n".join(lines)
)

# SQL keywords that trigger the regex
_sql_keywords = st.sampled_from(["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"])


@st.composite
def sql_concat_snippet(draw: st.DrawFn) -> str:
    """Generate Java code with SQL string concatenation (non-parameterized query).

    Generates patterns like: "SELECT * FROM users WHERE id = " + userId
    which match _RE_SQL_CONCAT.
    """
    keyword = draw(_sql_keywords)
    var_name = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    # Variant: "SQL_KEYWORD ..." + variable (the first alternative in _RE_SQL_CONCAT)
    variant = draw(st.sampled_from(["keyword_then_plus", "plus_then_keyword"]))

    if variant == "keyword_then_plus":
        # Matches: "SELECT..." + or similar pattern where SQL keyword is in the string
        # followed by quote-close and +
        pattern_line = f'String query = "{keyword} * FROM users WHERE id = " + {var_name};'
    else:
        # Matches: + "...SELECT..." (second alternative in _RE_SQL_CONCAT)
        pattern_line = (
            f'String query = baseQuery + " {keyword} * FROM table WHERE col = " + {var_name};'
        )

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


@st.composite
def jndi_lookup_snippet(draw: st.DrawFn) -> str:
    """Generate Java code with JNDI lookup using a dynamic (variable) name.

    Generates patterns like: new InitialContext().lookup(jndiName)
    which match _RE_JNDI_LOOKUP (non-string-literal argument).
    The regex matches: InitialContext().lookup(variable) or JndiTemplate.lookup(variable)
    where the argument is NOT a string literal.
    """
    var_name = draw(_identifier_strategy)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    # Choose between InitialContext (with parens for constructor) and JndiTemplate
    context_type = draw(st.sampled_from(["InitialContext", "JndiTemplate"]))

    if context_type == "InitialContext":
        # InitialContext().lookup(variable) - constructor call then lookup
        pattern_line = f"Object result = new InitialContext().lookup({var_name});"
    else:
        # JndiTemplate.lookup(variable) - class-level call
        pattern_line = f"Object result = JndiTemplate.lookup({var_name});"

    parts = [p for p in [prefix, pattern_line, suffix] if p]
    return "\n".join(parts)


@st.composite
def spring_tool_sql_snippet(draw: st.DrawFn) -> str:
    """Generate Java code with Spring AI @Tool method passing String params to SQL.

    Generates patterns like:
    @Tool
    public String query(String userInput) {
        String sql = "SELECT * FROM users WHERE name = " + userInput;
        ...
    }
    which match _RE_SPRING_TOOL_METHOD for SQL concatenation.
    """
    var_name = draw(_identifier_strategy)
    keyword = draw(_sql_keywords)
    prefix = draw(_padding_strategy)
    suffix = draw(_padding_strategy)

    pattern_lines = (
        f"@Tool\n"
        f"public String queryData(String {var_name}) {{\n"
        f'    String sql = "{keyword} * FROM users WHERE id = " + {var_name};\n'
        f"    return jdbcTemplate.queryForObject(sql, String.class);\n"
        f"}}"
    )

    parts = [p for p in [prefix, pattern_lines, suffix] if p]
    return "\n".join(parts)


# --- Property Tests ---


class TestSQLInjectionDetectionJava:
    """Property 5: SQL Injection Detection Across Languages (Java subset).

    **Validates: Requirements 3.4, 3.7**
    """

    @given(content=sql_concat_snippet())
    @settings(max_examples=100, deadline=None)
    def test_sql_concat_detected_as_mcp_s6(self, content: str) -> None:
        """Any Java code with SQL string concatenation (non-parameterized queries)
        SHALL produce at least one MCP-S6 finding."""
        scanner = JavaAnalyzer()
        findings = scanner.scan(content, ArtifactType.MCP, "UserRepository.java")

        mcp_s6_findings = [f for f in findings if f.id == "MCP-S6"]
        assert len(mcp_s6_findings) >= 1, (
            f"Expected at least one MCP-S6 finding for SQL concatenation pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )

    @given(content=jndi_lookup_snippet())
    @settings(max_examples=100, deadline=None)
    def test_jndi_lookup_detected_as_mcp_s6(self, content: str) -> None:
        """Any Java code with JNDI lookups using dynamic (variable) names
        SHALL produce at least one MCP-S6 finding."""
        scanner = JavaAnalyzer()
        findings = scanner.scan(content, ArtifactType.MCP, "ServiceLocator.java")

        mcp_s6_findings = [f for f in findings if f.id == "MCP-S6"]
        assert len(mcp_s6_findings) >= 1, (
            f"Expected at least one MCP-S6 finding for JNDI lookup pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )

    @given(content=spring_tool_sql_snippet())
    @settings(max_examples=100, deadline=None)
    def test_spring_tool_sql_detected_as_mcp_s6(self, content: str) -> None:
        """Any Java code with Spring AI @Tool methods passing String params to SQL
        SHALL produce at least one MCP-S6 finding."""
        scanner = JavaAnalyzer()
        findings = scanner.scan(content, ArtifactType.MCP, "McpToolService.java")

        mcp_s6_findings = [f for f in findings if f.id == "MCP-S6"]
        assert len(mcp_s6_findings) >= 1, (
            f"Expected at least one MCP-S6 finding for Spring AI @Tool SQL pattern.\n"
            f"Content:\n{content}\n"
            f"All findings: {[(f.id, f.confidence) for f in findings]}"
        )
