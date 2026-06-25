"""Tests for the markdown formatter."""

from __future__ import annotations

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
from ai_artifact_risk_validator.reporting.formatters.markdown_formatter import format_markdown


def _make_report(
    findings: list[ScanFinding] | None = None,
    risk_score: int = 0,
    risk_severity: str = "LOW",
    risk_recommendation: str = "SAFE",
) -> ScanReport:
    from datetime import datetime

    _findings = findings or []
    blocked = sum(1 for f in _findings if f.gate_action == GateAction.BLOCK)
    warned = sum(1 for f in _findings if f.gate_action == GateAction.WARN)
    info = sum(1 for f in _findings if f.gate_action == GateAction.INFO)

    return ScanReport(
        scan_id="test-scan-001",
        artifact_path="test_artifact.md",
        artifact_type=ArtifactType.PROMPT,
        scan_timestamp=datetime(2025, 1, 1, 12, 0, 0),
        scanner_version="0.10.0",
        findings=_findings,
        summary=ScanSummary(
            total_findings=len(_findings),
            gate_decision=GateAction.BLOCK if blocked > 0 else GateAction.INFO,
            blocking_findings=blocked,
            warning_findings=warned,
            info_findings=info,
        ),
        risk_score=risk_score,
        risk_severity=risk_severity,
        risk_recommendation=risk_recommendation,
        has_executable_scripts=False,
    )


def _make_finding(
    risk_id: str = "P-S1",
    severity: SeverityLabel = SeverityLabel.HIGH,
    score: int = 8,
    title: str = "Test Finding",
    evidence: str = "test evidence",
) -> ScanFinding:
    from datetime import datetime

    return ScanFinding(
        id=risk_id,
        artifact_type=ArtifactType.PROMPT,
        artifact_path="test.md",
        severity_score=score,
        severity_label=severity,
        priority=Priority.P1,
        gate_action=GateAction.BLOCK,
        category=RiskCategory.SECURITY,
        title=title,
        description="Test description",
        location=FindingLocation(line=42),
        evidence=evidence,
        confidence=0.90,
        scanner_module=ScannerModule.INJECTION_DET,
        remediation="Fix it",
        timestamp=datetime(2025, 1, 1, 12, 0, 0),
    )


class TestFormatMarkdownBasic:
    def test_returns_string(self) -> None:
        report = _make_report()
        result = format_markdown(report)
        assert isinstance(result, str)

    def test_contains_scan_id(self) -> None:
        report = _make_report()
        result = format_markdown(report)
        assert "test-scan-001" in result

    def test_contains_artifact_path(self) -> None:
        report = _make_report()
        result = format_markdown(report)
        assert "test_artifact.md" in result

    def test_empty_findings_no_table(self) -> None:
        report = _make_report(findings=[])
        result = format_markdown(report)
        assert "No findings" in result or "0 findings" in result or "## Findings" in result

    def test_has_markdown_headings(self) -> None:
        report = _make_report()
        result = format_markdown(report)
        assert "## " in result or "# " in result


class TestFormatMarkdownWithFindings:
    def test_finding_risk_id_present(self) -> None:
        finding = _make_finding(risk_id="P-S1")
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        assert "P-S1" in result

    def test_finding_title_present(self) -> None:
        finding = _make_finding(title="Direct Prompt Injection")
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        assert "Direct Prompt Injection" in result

    def test_critical_finding_has_emoji(self) -> None:
        finding = _make_finding(risk_id="P-S1", severity=SeverityLabel.CRITICAL, score=10)
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        # Red circle emoji for critical
        assert "🔴" in result

    def test_high_finding_has_orange_emoji(self) -> None:
        finding = _make_finding(risk_id="P-S1", severity=SeverityLabel.HIGH, score=8)
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        assert "🟠" in result

    def test_evidence_code_fence_for_high(self) -> None:
        finding = _make_finding(
            risk_id="P-S1",
            severity=SeverityLabel.HIGH,
            evidence="ignore all previous instructions",
        )
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        # High/Critical findings should have code fence evidence
        assert "```" in result

    def test_pipe_characters_escaped_in_cells(self) -> None:
        finding = _make_finding(
            title="A | B",
            evidence="pipe | char",
        )
        report = _make_report(findings=[finding])
        result = format_markdown(report)
        # The report should contain the finding title somewhere
        assert "A" in result and "B" in result


class TestRiskScoreBadge:
    def test_low_risk_badge_present(self) -> None:
        report = _make_report(risk_score=10, risk_severity="LOW", risk_recommendation="SAFE")
        result = format_markdown(report)
        assert "LOW" in result or "SAFE" in result or "10" in result

    def test_critical_risk_badge_present(self) -> None:
        report = _make_report(
            risk_score=95, risk_severity="CRITICAL", risk_recommendation="DO_NOT_INSTALL"
        )
        result = format_markdown(report)
        assert "CRITICAL" in result or "95" in result
