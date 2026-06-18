"""Markdown output formatter for scan reports.

Formats a ScanReport as GitHub-Flavored Markdown (GFM), suitable for:
- Pasting directly into GitHub/GitLab PR comments
- Documentation site embeds
- README security sections

Output uses GFM tables, code-fenced evidence snippets, and severity emoji.
No HTML is used — the output is pure Markdown.
"""

from __future__ import annotations

from ai_artifact_risk_validator.models.enums import GateAction, SeverityLabel
from ai_artifact_risk_validator.models.report import ScanReport

_GATE_EMOJI: dict[GateAction, str] = {
    GateAction.BLOCK: "🔴",
    GateAction.WARN: "🟡",
    GateAction.INFO: "🟢",
}

_SEVERITY_EMOJI: dict[SeverityLabel, str] = {
    SeverityLabel.CRITICAL: "🔴",
    SeverityLabel.HIGH: "🟠",
    SeverityLabel.MEDIUM: "🟡",
    SeverityLabel.LOW: "🔵",
    SeverityLabel.INFORMATIONAL: "⚪",
}

_RECOMMENDATION_BADGE: dict[str, str] = {
    "SAFE": "✅ SAFE",
    "CAUTION": "⚠️ CAUTION",
    "DO_NOT_INSTALL": "🚫 DO NOT USE",
}


def format_markdown(report: ScanReport) -> str:
    """Format a ScanReport as GitHub-Flavored Markdown.

    Produces a self-contained Markdown document with:
    - Risk score badge and recommendation
    - Summary table (gate decision, finding counts)
    - Findings table with severity emoji, risk ID, title, file, and line
    - Evidence snippets in code fences for high/critical findings
    - Errors section (if any)

    Args:
        report: The ScanReport to format.

    Returns:
        A GFM-compliant Markdown string.
    """
    lines: list[str] = []

    gate = report.summary.gate_decision
    gate_emoji = _GATE_EMOJI.get(gate, "⚪")
    recommendation = _RECOMMENDATION_BADGE.get(
        report.risk_recommendation, report.risk_recommendation
    )

    # Header
    lines.append("## AI Artifact Risk Validation Report")
    lines.append("")
    lines.append(
        f"**Risk Score:** {report.risk_score}/100 — **{report.risk_severity}** {recommendation}"
    )
    lines.append("")

    # Metadata table
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Scan ID | `{report.scan_id}` |")
    lines.append(f"| Path | `{report.artifact_path}` |")
    lines.append(f"| Timestamp | {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |")
    lines.append(f"| Version | {report.scanner_version} |")
    lines.append(f"| Gate Decision | {gate_emoji} **{gate.value}** |")
    if report.has_executable_scripts:
        lines.append("| Executable Scripts | \u26a0\ufe0f Yes (1.3x risk multiplier applied) |")
    lines.append("")

    # Summary counts
    s = report.summary
    lines.append("### Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Findings | {s.total_findings} |")
    lines.append(f"| 🔴 Blocking | {s.blocking_findings} |")
    lines.append(f"| 🟡 Warnings | {s.warning_findings} |")
    lines.append(f"| 🟢 Info | {s.info_findings} |")
    lines.append("")

    # Findings table
    if report.findings:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Sev | Risk ID | Title | File | Line |")
        lines.append("|-----|---------|-------|------|------|")

        for finding in report.findings:
            sev_emoji = _SEVERITY_EMOJI.get(finding.severity_label, "⚪")
            sev_label = finding.severity_label.value
            line_str = str(finding.location.line) if finding.location.line else "—"
            fp_suffix = " *(suppressed)*" if finding.false_positive else ""
            # Escape pipe characters in title/path for table safety
            title = finding.title.replace("|", "\\|")
            fpath = finding.artifact_path.replace("|", "\\|")

            lines.append(
                f"| {sev_emoji} {sev_label} | `{finding.id}` "
                f"| {title}{fp_suffix} | `{fpath}` | {line_str} |"
            )

        lines.append("")

        # Evidence snippets for BLOCK-gate / High+ findings
        high_findings = [
            f
            for f in report.findings
            if not f.false_positive
            and f.severity_label in (SeverityLabel.CRITICAL, SeverityLabel.HIGH)
            and f.evidence
        ]
        if high_findings:
            lines.append("### Evidence (High+ Severity)")
            lines.append("")
            for finding in high_findings[:10]:  # cap at 10 to avoid huge comments
                lines.append(f"**`{finding.id}` — {finding.title}**")
                lines.append("")
                if finding.location.line:
                    lines.append(f"*{finding.artifact_path}:{finding.location.line}*")
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence[:300])  # truncate very long evidence
                lines.append("```")
                lines.append("")
                if finding.explanation:
                    lines.append(f"> {finding.explanation}")
                    lines.append("")
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append("")
    else:
        lines.append("### Findings")
        lines.append("")
        lines.append("✅ No findings detected.")
        lines.append("")

    # Errors section
    if report.errors:
        lines.append("### Errors")
        lines.append("")
        for error in report.errors:
            lines.append(f"- {error}")
        lines.append("")

    return "\n".join(lines)
