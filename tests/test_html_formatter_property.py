"""Property-based tests for the HTML formatter.

Uses Hypothesis to verify correctness properties of format_html()
across randomly generated ScanReport inputs.
"""

from __future__ import annotations

import html
import string
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import (
    ArtifactType,
    GateAction,
    Priority,
    RiskCategory,
    ScannerModule,
    SeverityLabel,
)
from ai_artifact_risk_validator.models.findings import FindingLocation, ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport, ScanSummary
from ai_artifact_risk_validator.reporting.formatters.html_formatter import format_html

# --- Hypothesis strategies for generating valid model instances ---

valid_id_strategy = st.from_regex(r"^[A-Z]+-[A-Z]?[0-9]+$", fullmatch=True)

valid_severity_score_strategy = st.integers(min_value=1, max_value=10)

valid_confidence_strategy = st.floats(
    min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False
)

valid_artifact_type_strategy = st.sampled_from(list(ArtifactType))

valid_severity_label_strategy = st.sampled_from(list(SeverityLabel))

valid_priority_strategy = st.sampled_from(list(Priority))

valid_gate_action_strategy = st.sampled_from(list(GateAction))

valid_category_strategy = st.sampled_from(list(RiskCategory))

valid_scanner_module_strategy = st.sampled_from(list(ScannerModule))

valid_non_empty_text = st.text(
    alphabet=string.ascii_letters + string.digits + " _-./",
    min_size=1,
    max_size=50,
)

valid_datetime_strategy = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31),
).map(lambda dt: dt.replace(microsecond=0, tzinfo=timezone.utc))


@st.composite
def valid_finding_location(draw: st.DrawFn) -> FindingLocation:
    """Generate a valid FindingLocation with optional fields."""
    return FindingLocation(
        line=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000))),
        end_line=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=10000))),
        section=draw(st.one_of(st.none(), valid_non_empty_text)),
        offset=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100000))),
    )


@st.composite
def valid_scan_finding(draw: st.DrawFn) -> ScanFinding:
    """Generate a valid ScanFinding object."""
    return ScanFinding(
        id=draw(valid_id_strategy),
        artifact_type=draw(valid_artifact_type_strategy),
        artifact_path=draw(valid_non_empty_text),
        severity_score=draw(valid_severity_score_strategy),
        severity_label=draw(valid_severity_label_strategy),
        priority=draw(valid_priority_strategy),
        gate_action=draw(valid_gate_action_strategy),
        category=draw(valid_category_strategy),
        title=draw(valid_non_empty_text),
        description=draw(valid_non_empty_text),
        location=draw(valid_finding_location()),
        evidence=draw(valid_non_empty_text),
        confidence=draw(valid_confidence_strategy),
        scanner_module=draw(valid_scanner_module_strategy),
        remediation=draw(valid_non_empty_text),
        references=draw(st.lists(valid_non_empty_text, min_size=0, max_size=5)),
        false_positive=draw(st.booleans()),
        timestamp=draw(valid_datetime_strategy),
    )


def _build_scan_summary(findings: list[ScanFinding]) -> ScanSummary:
    """Build a valid ScanSummary computed from findings."""
    total_findings = len(findings)

    by_severity: dict[str, int] = {}
    for f in findings:
        label = f.severity_label.value
        by_severity[label] = by_severity.get(label, 0) + 1

    by_category: dict[str, int] = {}
    for f in findings:
        cat = f.category.value
        by_category[cat] = by_category.get(cat, 0) + 1

    blocking = sum(
        1 for f in findings if f.gate_action == GateAction.BLOCK and not f.false_positive
    )
    warning = sum(
        1 for f in findings if f.gate_action == GateAction.WARN and not f.false_positive
    )
    info = sum(
        1 for f in findings if f.gate_action == GateAction.INFO and not f.false_positive
    )

    if blocking > 0:
        gate_decision = GateAction.BLOCK
    elif warning > 0:
        gate_decision = GateAction.WARN
    else:
        gate_decision = GateAction.INFO

    return ScanSummary(
        total_findings=total_findings,
        by_severity=by_severity,
        by_category=by_category,
        gate_decision=gate_decision,
        blocking_findings=blocking,
        warning_findings=warning,
        info_findings=info,
    )


@st.composite
def valid_scan_report(draw: st.DrawFn) -> ScanReport:
    """Generate a valid ScanReport with random findings and computed summary."""
    findings = draw(st.lists(valid_scan_finding(), min_size=0, max_size=10))
    summary = _build_scan_summary(findings)

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_non_empty_text),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings,
        summary=summary,
        errors=draw(st.lists(valid_non_empty_text, min_size=0, max_size=3)),
    )


@st.composite
def scan_report_with_errors(draw: st.DrawFn) -> ScanReport:
    """Generate a valid ScanReport with at least one error message."""
    findings = draw(st.lists(valid_scan_finding(), min_size=0, max_size=5))
    summary = _build_scan_summary(findings)
    errors = draw(st.lists(st.text(min_size=1), min_size=1, max_size=5))

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_non_empty_text),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings,
        summary=summary,
        errors=errors,
    )


# --- Property Tests ---


# Feature: standalone-html-report, Property 1: Structural validity
class TestHtmlStructuralValidity:
    """Property 1: Structural validity — valid HTML5 with inline CSS and no external resources.

    **Validates: Requirements 1.1, 1.2**

    For any valid ScanReport (with any combination of findings, errors, metadata),
    format_html(report) SHALL produce a string that:
    - Contains <!DOCTYPE html>, <html, </html>, <head>, </head>, <body>, </body>
    - Contains a <style> element with CSS content
    - Does NOT contain any references to external resources
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100)
    def test_output_contains_required_html5_structure(self, report: ScanReport) -> None:
        """format_html output must contain all required HTML5 structural elements."""
        output = format_html(report)

        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output
        assert "<head>" in output
        assert "</head>" in output
        assert "<body>" in output
        assert "</body>" in output

    @given(report=valid_scan_report())
    @settings(max_examples=100)
    def test_output_contains_inline_style_element(self, report: ScanReport) -> None:
        """format_html output must contain a <style> element with CSS content."""
        output = format_html(report)

        assert "<style>" in output

    @given(report=valid_scan_report())
    @settings(max_examples=100)
    def test_output_has_no_external_resource_references(self, report: ScanReport) -> None:
        """format_html output must NOT reference any external resources."""
        output = format_html(report)

        assert 'href="http' not in output
        assert 'src="http' not in output
        assert "url(http" not in output
        assert '<link rel="stylesheet" href=' not in output


# Feature: standalone-html-report, Property 2: Summary section completeness
class TestSummarySectionCompleteness:
    """Property 2: Summary section completeness.

    **Validates: Requirements 1.3**

    For any valid ScanReport, the output of format_html(report) SHALL contain
    the report's scan_id, artifact_path, ISO-formatted scan_timestamp,
    scanner_version, gate_decision value, total_findings count,
    blocking_findings count, warning_findings count, and info_findings count
    as escaped text within the document.
    """

    @given(report=valid_scan_report())
    @settings(max_examples=100)
    def test_summary_contains_all_required_fields(self, report: ScanReport) -> None:
        """Assert all summary fields appear HTML-escaped in the output."""
        output = format_html(report)

        # scan_id must appear escaped
        assert html.escape(report.scan_id, quote=True) in output

        # artifact_path must appear escaped
        assert html.escape(report.artifact_path, quote=True) in output

        # scan_timestamp in ISO format must appear escaped
        assert html.escape(report.scan_timestamp.isoformat(), quote=True) in output

        # scanner_version must appear escaped
        assert html.escape(report.scanner_version, quote=True) in output

        # gate_decision value must appear escaped
        assert html.escape(report.summary.gate_decision.value, quote=True) in output

        # total_findings count must appear
        assert str(report.summary.total_findings) in output

        # blocking_findings count must appear
        assert str(report.summary.blocking_findings) in output

        # warning_findings count must appear
        assert str(report.summary.warning_findings) in output

        # info_findings count must appear
        assert str(report.summary.info_findings) in output


@st.composite
def scan_finding_with_fp(draw: st.DrawFn, false_positive: bool) -> ScanFinding:
    """Generate a valid ScanFinding with a specific false_positive value."""
    return ScanFinding(
        id=draw(valid_id_strategy),
        artifact_type=draw(valid_artifact_type_strategy),
        artifact_path=draw(valid_non_empty_text),
        severity_score=draw(valid_severity_score_strategy),
        severity_label=draw(valid_severity_label_strategy),
        priority=draw(valid_priority_strategy),
        gate_action=draw(valid_gate_action_strategy),
        category=draw(valid_category_strategy),
        title=draw(valid_non_empty_text),
        description=draw(valid_non_empty_text),
        location=draw(valid_finding_location()),
        evidence=draw(valid_non_empty_text),
        confidence=draw(valid_confidence_strategy),
        scanner_module=draw(valid_scanner_module_strategy),
        remediation=draw(valid_non_empty_text),
        references=draw(st.lists(valid_non_empty_text, min_size=0, max_size=3)),
        false_positive=false_positive,
        timestamp=draw(valid_datetime_strategy),
    )


@st.composite
def scan_report_with_suppressed_and_active(draw: st.DrawFn) -> ScanReport:
    """Generate a ScanReport with at least one suppressed and one active finding.

    Guarantees:
    - At least one finding with false_positive=True (suppressed)
    - At least one finding with false_positive=False (active)
    """
    suppressed_findings = draw(
        st.lists(scan_finding_with_fp(false_positive=True), min_size=1, max_size=3)
    )
    active_findings = draw(
        st.lists(scan_finding_with_fp(false_positive=False), min_size=1, max_size=3)
    )
    all_findings = suppressed_findings + active_findings
    findings = draw(st.permutations(all_findings))
    findings_list = list(findings)

    summary = _build_scan_summary(findings_list)

    return ScanReport(
        scan_id=draw(st.uuids().map(str)),
        artifact_path=draw(valid_non_empty_text),
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)),
        findings=findings_list,
        summary=summary,
        errors=draw(st.lists(valid_non_empty_text, min_size=0, max_size=3)),
    )


# Feature: standalone-html-report, Property 6: Suppressed finding visual distinction
class TestSuppressedFindingVisualDistinction:
    """Property 6: Suppressed finding visual distinction.

    **Validates: Requirements 4.3**

    For any valid ScanReport containing at least one finding with
    false_positive=True, the rendered HTML for that finding SHALL include
    a distinguishing CSS class (class="finding-card suppressed") that is
    NOT present on findings with false_positive=False.
    """

    @given(report=scan_report_with_suppressed_and_active())
    @settings(max_examples=100)
    def test_suppressed_findings_have_suppressed_class(self, report: ScanReport) -> None:
        """Findings with false_positive=True have 'suppressed' class;
        findings with false_positive=False do NOT have 'suppressed' class.
        """
        html_output = format_html(report)

        # Split by 'class="finding-card' to isolate each card fragment
        # The output renders cards in the same order as report.findings
        cards = html_output.split('class="finding-card')
        # First element is everything before the first finding card
        finding_cards = cards[1:]

        assert len(finding_cards) == len(report.findings), (
            f"Expected {len(report.findings)} finding cards, "
            f"found {len(finding_cards)}"
        )

        for i, finding in enumerate(report.findings):
            card_fragment = finding_cards[i]
            if finding.false_positive:
                # Suppressed card starts with ' suppressed">'
                assert card_fragment.startswith(' suppressed"'), (
                    f"Finding {finding.id} (index {i}) has false_positive=True "
                    f"but its card does not have the 'suppressed' class. "
                    f"Card starts with: {card_fragment[:50]}"
                )
            else:
                # Active card should NOT start with ' suppressed'
                assert not card_fragment.startswith(' suppressed'), (
                    f"Finding {finding.id} (index {i}) has false_positive=False "
                    f"but its card has the 'suppressed' class. "
                    f"Card starts with: {card_fragment[:50]}"
                )


# Feature: standalone-html-report, Property 3: Finding content completeness
class TestFindingContentCompleteness:
    """Property 3: Finding content completeness with evidence snippet.

    **Validates: Requirements 1.4, 1.5**

    For any valid ScanReport containing one or more findings, the output
    of format_html(report) SHALL contain each finding's id, title,
    severity_label value, category value, and description as escaped text.
    Additionally, for each finding with non-empty evidence, the evidence
    text SHALL appear within a code-formatted block (<pre> or <code> element).
    """

    @given(
        report=valid_scan_report().filter(lambda r: len(r.findings) > 0),
    )
    @settings(max_examples=100)
    def test_finding_fields_appear_as_escaped_text(self, report: ScanReport) -> None:
        """Each finding's id, title, severity_label, category, and description
        appear as HTML-escaped text in the output."""
        output = format_html(report)

        for finding in report.findings:
            escaped_id = html.escape(finding.id, quote=True)
            escaped_title = html.escape(finding.title, quote=True)
            escaped_severity = html.escape(finding.severity_label.value, quote=True)
            escaped_category = html.escape(finding.category.value, quote=True)
            escaped_description = html.escape(finding.description, quote=True)

            assert escaped_id in output, (
                f"Finding id '{escaped_id}' not found in HTML output"
            )
            assert escaped_title in output, (
                f"Finding title '{escaped_title}' not found in HTML output"
            )
            assert escaped_severity in output, (
                f"Severity label '{escaped_severity}' not found in HTML output"
            )
            assert escaped_category in output, (
                f"Category '{escaped_category}' not found in HTML output"
            )
            assert escaped_description in output, (
                f"Description '{escaped_description}' not found in HTML output"
            )

    @given(
        report=valid_scan_report().filter(
            lambda r: any(f.evidence for f in r.findings)
        ),
    )
    @settings(max_examples=100)
    def test_evidence_appears_in_code_block(self, report: ScanReport) -> None:
        """For findings with non-empty evidence, the escaped evidence text
        appears within <pre> and </pre> or <code> and </code> elements."""
        import re

        output = format_html(report)

        for finding in report.findings:
            if finding.evidence:
                escaped_evidence = html.escape(finding.evidence, quote=True)
                # Verify evidence appears between <pre><code> and </code></pre>
                pre_pattern = re.compile(
                    r"<pre><code>.*?"
                    + re.escape(escaped_evidence)
                    + r".*?</code></pre>",
                    re.DOTALL,
                )
                assert pre_pattern.search(output), (
                    f"Evidence for finding '{finding.id}' not found within "
                    f"<pre><code>...</code></pre> block in HTML output"
                )


# Feature: standalone-html-report, Property 4: Error message inclusion
class TestErrorMessageInclusion:
    """Property 4: Error message inclusion.

    **Validates: Requirements 1.6**

    For any valid ScanReport containing one or more error messages,
    the output of format_html(report) SHALL contain each error message
    (HTML-escaped) in the rendered document.
    """

    @given(report=scan_report_with_errors())
    @settings(max_examples=100)
    def test_all_error_messages_appear_html_escaped_in_output(
        self, report: ScanReport
    ) -> None:
        """All error messages from report.errors appear HTML-escaped in the output."""
        output = format_html(report)

        for error_msg in report.errors:
            escaped_msg = html.escape(error_msg, quote=True)
            assert escaped_msg in output, (
                f"Expected escaped error message {escaped_msg!r} to appear in HTML output"
            )


# --- Adversarial string strategy for XSS testing ---

_XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<script>document.cookie</script>",
    '<img src="x" onerror="alert(1)">',
    "<svg onload=alert(1)>",
    "<<script>alert('nested')</script>",
    '<a href="javascript:alert(1)">click</a>',
]

adversarial_text = st.one_of(
    # Pure XSS payloads
    st.sampled_from(_XSS_PAYLOADS),
    # Text containing HTML special characters mixed with normal text
    st.text(
        alphabet=st.sampled_from(
            list('<>&"\'') + list(string.ascii_letters + string.digits + " ")
        ),
        min_size=1,
        max_size=80,
    ),
    # Text with embedded script tags
    st.builds(
        lambda prefix, suffix: f"{prefix}<script>alert('xss')</script>{suffix}",
        prefix=st.text(
            alphabet=string.ascii_letters + string.digits + " ", min_size=0, max_size=20
        ),
        suffix=st.text(
            alphabet=string.ascii_letters + string.digits + " ", min_size=0, max_size=20
        ),
    ),
)


@st.composite
def adversarial_scan_report(draw: st.DrawFn) -> ScanReport:
    """Generate a ScanReport with adversarial XSS strings in all text fields.

    Injects adversarial strings into scan_id, artifact_path, finding title,
    description, evidence, and error messages.
    """
    adversarial_scan_id = draw(adversarial_text)
    adversarial_artifact_path = draw(adversarial_text)
    adversarial_errors = draw(st.lists(adversarial_text, min_size=1, max_size=3))

    # Create findings with adversarial strings in title, description, evidence
    findings = draw(
        st.lists(
            st.builds(
                ScanFinding,
                id=valid_id_strategy,
                artifact_type=valid_artifact_type_strategy,
                artifact_path=adversarial_text,
                severity_score=valid_severity_score_strategy,
                severity_label=valid_severity_label_strategy,
                priority=valid_priority_strategy,
                gate_action=valid_gate_action_strategy,
                category=valid_category_strategy,
                title=adversarial_text,
                description=adversarial_text,
                location=valid_finding_location(),
                evidence=adversarial_text,
                confidence=valid_confidence_strategy,
                scanner_module=valid_scanner_module_strategy,
                remediation=adversarial_text,
                references=st.lists(adversarial_text, min_size=0, max_size=3),
                false_positive=st.booleans(),
                timestamp=valid_datetime_strategy,
            ),
            min_size=1,
            max_size=5,
        )
    )

    summary = _build_scan_summary(findings)

    return ScanReport(
        scan_id=adversarial_scan_id,
        artifact_path=adversarial_artifact_path,
        artifact_type=draw(st.one_of(st.none(), valid_artifact_type_strategy)),
        scan_timestamp=draw(valid_datetime_strategy),
        scanner_version=draw(
            st.from_regex(r"^[0-9]+\.[0-9]+\.[0-9]+$", fullmatch=True)
        ),
        findings=findings,
        summary=summary,
        errors=adversarial_errors,
    )


# Feature: standalone-html-report, Property 5: XSS prevention
class TestXssPreventionViaHtmlEntityEscaping:
    """Property 5: XSS prevention via HTML entity escaping.

    **Validates: Requirements 1.7**

    For any valid ScanReport where any text field (scan_id, artifact_path,
    finding title, description, evidence, error messages) contains HTML
    special characters (<, >, &, ", '), the output of format_html(report)
    SHALL NOT contain those characters unescaped in content positions.
    Specifically, any <script substring present in input fields SHALL NOT
    appear as a raw <script in the output; it SHALL appear as &lt;script instead.
    """

    @given(report=adversarial_scan_report())
    @settings(max_examples=100)
    def test_no_raw_script_tag_in_output(self, report: ScanReport) -> None:
        """Assert no raw <script appears in output; it must be &lt;script.

        Verifies that adversarial strings containing <script> tags are
        properly escaped in the HTML output, preventing XSS attacks.
        """
        output = format_html(report)

        # Collect all text fields that might contain <script
        text_fields = [report.scan_id, report.artifact_path] + report.errors
        for finding in report.findings:
            text_fields.extend(
                [
                    finding.title,
                    finding.description,
                    finding.evidence,
                    finding.artifact_path,
                    finding.remediation,
                ]
            )
            text_fields.extend(finding.references)

        # If any input contains <script, verify it does NOT appear raw in output
        has_script_input = any("<script" in field for field in text_fields)

        if has_script_input:
            # The output should contain &lt;script (escaped form) but not
            # raw <script in user-content positions.
            # We check by removing known safe occurrences of <style> (which is
            # the template's own style tag) and verifying no <script remains.
            # The HTML template itself does not use any <script> tags.
            assert "<script" not in output, (
                "Raw <script found in HTML output — XSS vulnerability! "
                "All user content must be HTML-entity-escaped."
            )
            # Verify the escaped version is present
            assert "&lt;script" in output, (
                "Expected &lt;script to appear in output since input contained "
                "<script, but it was not found."
            )
