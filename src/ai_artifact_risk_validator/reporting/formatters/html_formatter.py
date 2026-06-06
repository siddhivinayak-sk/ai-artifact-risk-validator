"""HTML output formatter for scan reports.

Formats a ScanReport as a standalone HTML page with inline CSS
for portability. Includes a summary section and detailed finding cards
with evidence snippets.
"""

from __future__ import annotations

import html as html_lib

from ai_artifact_risk_validator.models.enums import GateAction, SeverityLabel
from ai_artifact_risk_validator.models.findings import ScanFinding
from ai_artifact_risk_validator.models.report import ScanReport

_GATE_COLOR = {
    GateAction.BLOCK: "#dc3545",
    GateAction.WARN: "#ffc107",
    GateAction.INFO: "#28a745",
}

_SEVERITY_COLOR = {
    SeverityLabel.CRITICAL: "#dc3545",
    SeverityLabel.HIGH: "#e74c3c",
    SeverityLabel.MEDIUM: "#f39c12",
    SeverityLabel.LOW: "#17a2b8",
    SeverityLabel.INFORMATIONAL: "#6c757d",
}


def _escape(value: str) -> str:
    """HTML-escape a string using html.escape()."""
    return html_lib.escape(value, quote=True)


def _render_evidence_snippet(evidence: str) -> str:
    """Render evidence text in a <pre><code> block.

    Args:
        evidence: The raw evidence text to render.

    Returns:
        HTML string containing the evidence in a code block,
        or empty string if evidence is empty.
    """
    if not evidence:
        return ""
    return f"""    <div class="evidence-snippet">
      <pre><code>{_escape(evidence)}</code></pre>
    </div>"""


def _render_finding_detail(finding: ScanFinding) -> str:
    """Render a single finding as a detailed card with all fields.

    Args:
        finding: The ScanFinding to render.

    Returns:
        HTML string containing the full finding card.
    """
    sev_color = _SEVERITY_COLOR.get(finding.severity_label, "#333")
    suppressed_class = " suppressed" if finding.false_positive else ""

    # Location details
    line_str = str(finding.location.line) if finding.location.line is not None else "&mdash;"
    end_line_str = (
        str(finding.location.end_line) if finding.location.end_line is not None else "&mdash;"
    )
    section_str = _escape(finding.location.section) if finding.location.section else "&mdash;"

    # References
    if finding.references:
        refs_html = ", ".join(_escape(ref) for ref in finding.references)
    else:
        refs_html = "&mdash;"

    # Evidence snippet
    evidence_html = _render_evidence_snippet(finding.evidence)

    return f"""  <div class="finding-card{suppressed_class}">
    <div class="finding-header">
      <span class="severity-badge" style="background:{sev_color}">{_escape(finding.severity_label.value)} (S{finding.severity_score})</span>
      <span class="finding-id">{_escape(finding.id)}</span>
      <span class="finding-title">{_escape(finding.title)}</span>
    </div>
    <div class="finding-details">
      <table>
        <tr><td>Risk ID</td><td>{_escape(finding.id)}</td></tr>
        <tr><td>Artifact Type</td><td>{_escape(finding.artifact_type.value)}</td></tr>
        <tr><td>Artifact Path</td><td>{_escape(finding.artifact_path)}</td></tr>
        <tr><td>Severity Score</td><td>{finding.severity_score}</td></tr>
        <tr><td>Severity Label</td><td>{_escape(finding.severity_label.value)}</td></tr>
        <tr><td>Priority</td><td>{_escape(finding.priority.value)}</td></tr>
        <tr><td>Gate Action</td><td>{_escape(finding.gate_action.value)}</td></tr>
        <tr><td>Category</td><td>{_escape(finding.category.value)}</td></tr>
        <tr><td>Title</td><td>{_escape(finding.title)}</td></tr>
        <tr><td>Description</td><td>{_escape(finding.description)}</td></tr>
        <tr><td>Line</td><td>{line_str}</td></tr>
        <tr><td>End Line</td><td>{end_line_str}</td></tr>
        <tr><td>Section</td><td>{section_str}</td></tr>
        <tr><td>Confidence</td><td>{finding.confidence}</td></tr>
        <tr><td>Scanner Module</td><td>{_escape(finding.scanner_module.value)}</td></tr>
        <tr><td>Remediation</td><td>{_escape(finding.remediation)}</td></tr>
        <tr><td>References</td><td>{refs_html}</td></tr>
        <tr><td>False Positive</td><td>{"Yes" if finding.false_positive else "No"}</td></tr>
      </table>
    </div>
{evidence_html}
  </div>"""


def _render_findings_section(report: ScanReport) -> str:
    """Render the findings section — cards or 'no findings' message."""
    if not report.findings:
        return '  <p class="no-findings">No findings detected.</p>'

    cards = "\n".join(_render_finding_detail(f) for f in report.findings)
    return cards


def _render_summary_section(report: ScanReport) -> str:
    """Render the summary table with scan metadata and counts."""
    gate = report.summary.gate_decision
    gate_color = _GATE_COLOR.get(gate, "#333")

    return f"""  <table class="summary-table">
    <tr><td>Scan ID</td><td>{_escape(report.scan_id)}</td></tr>
    <tr><td>Path</td><td>{_escape(report.artifact_path)}</td></tr>
    <tr><td>Timestamp</td><td>{_escape(report.scan_timestamp.isoformat())}</td></tr>
    <tr><td>Version</td><td>{_escape(report.scanner_version)}</td></tr>
    <tr>
      <td>Gate Decision</td>
      <td><span class="gate-badge" style="background:{gate_color}">{_escape(gate.value)}</span></td>
    </tr>
    <tr><td>Total Findings</td><td>{report.summary.total_findings}</td></tr>
    <tr><td>Blocking</td><td>{report.summary.blocking_findings}</td></tr>
    <tr><td>Warnings</td><td>{report.summary.warning_findings}</td></tr>
    <tr><td>Info</td><td>{report.summary.info_findings}</td></tr>
  </table>"""


def _render_errors_section(errors: list[str]) -> str:
    """Render the errors list if present.

    Args:
        errors: List of error message strings.

    Returns:
        HTML string for the errors section, or empty string if no errors.
    """
    if not errors:
        return ""
    error_items = "\n".join(f"        <li>{_escape(e)}</li>" for e in errors)
    return f"""
    <div class="errors">
      <h2>Errors</h2>
      <ul>
{error_items}
      </ul>
    </div>"""


def format_html(report: ScanReport) -> str:
    """Format a ScanReport as a self-contained HTML page.

    Produces a complete HTML5 document with all CSS styles inline within
    a <style> element. All user-provided content is HTML-entity-escaped
    to prevent XSS.

    Args:
        report: The ScanReport to format.

    Returns:
        A string containing the complete standalone HTML document.
    """
    summary_section = _render_summary_section(report)
    findings_section = _render_findings_section(report)
    errors_section = _render_errors_section(report.errors)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Artifact Risk Validator — Scan Report</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f8f9fa;
      color: #212529;
      padding: 2rem;
      line-height: 1.6;
    }}
    h1 {{
      font-size: 1.5rem;
      margin-bottom: 1.5rem;
      color: #343a40;
    }}
    h2 {{
      font-size: 1.2rem;
      margin: 1.5rem 0 0.75rem;
      color: #495057;
    }}
    .summary-table {{
      border-collapse: collapse;
      margin-bottom: 1.5rem;
    }}
    .summary-table td {{
      padding: 0.4rem 1rem 0.4rem 0;
      vertical-align: top;
    }}
    .summary-table td:first-child {{
      font-weight: 600;
      white-space: nowrap;
    }}
    .gate-badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      color: #fff;
      font-weight: 700;
      font-size: 0.9rem;
    }}
    .finding-card {{
      background: #fff;
      border: 1px solid #dee2e6;
      border-radius: 6px;
      margin-bottom: 1rem;
      padding: 1rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    }}
    .finding-card.suppressed {{
      opacity: 0.6;
      border-left: 4px solid #6c757d;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }}
    .finding-header .finding-id {{
      font-family: monospace;
      font-weight: 600;
      color: #495057;
    }}
    .finding-header .finding-title {{
      font-weight: 600;
      color: #212529;
    }}
    .finding-details {{
      margin-bottom: 0.75rem;
    }}
    .finding-details table {{
      border-collapse: collapse;
      width: 100%;
    }}
    .finding-details td {{
      padding: 0.3rem 0.75rem 0.3rem 0;
      vertical-align: top;
      font-size: 0.85rem;
      border-bottom: 1px solid #f1f3f5;
    }}
    .finding-details td:first-child {{
      font-weight: 600;
      white-space: nowrap;
      width: 140px;
      color: #495057;
    }}
    .evidence-snippet {{
      background: #f8f9fa;
      border: 1px solid #e9ecef;
      border-radius: 4px;
      padding: 0.75rem;
      overflow-x: auto;
    }}
    .evidence-snippet pre {{
      margin: 0;
    }}
    .evidence-snippet code {{
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.82rem;
      color: #212529;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    .severity-badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
      color: #fff;
      font-size: 0.8rem;
      font-weight: 600;
    }}
    .no-findings {{
      color: #28a745;
      font-weight: 600;
      margin: 1rem 0;
    }}
    .errors {{
      margin-top: 1.5rem;
    }}
    .errors ul {{
      list-style: disc;
      padding-left: 1.5rem;
    }}
    .errors li {{
      color: #856404;
      margin-bottom: 0.25rem;
    }}
  </style>
</head>
<body>
  <h1>AI Artifact Risk Validator &mdash; Scan Report</h1>

{summary_section}

  <h2>Findings</h2>
{findings_section}
{errors_section}
</body>
</html>"""
