"""HTML output formatter for scan reports.

Formats a ScanReport as a standalone HTML page with inline CSS
for portability. Includes a summary section and a findings table.
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


def format_html(report: ScanReport) -> str:
    """Format a ScanReport as a self-contained HTML page.

    Produces a complete HTML document with inline CSS styling,
    including a summary table and a findings table.

    Args:
        report: The ScanReport to format.

    Returns:
        A string containing the complete HTML document.
    """
    gate = report.summary.gate_decision
    gate_color = _GATE_COLOR.get(gate, "#333")

    findings_rows = "\n".join(_render_finding_row(f) for f in report.findings)

    errors_section = ""
    if report.errors:
        error_items = "\n".join(
            f"        <li>{html_lib.escape(e)}</li>" for e in report.errors
        )
        errors_section = f"""
    <div class="errors">
      <h2>Errors</h2>
      <ul>
{error_items}
      </ul>
    </div>"""

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
    .findings-table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.5rem;
      background: #fff;
      border: 1px solid #dee2e6;
      border-radius: 4px;
      overflow: hidden;
    }}
    .findings-table th {{
      background: #343a40;
      color: #fff;
      padding: 0.6rem 0.75rem;
      text-align: left;
      font-size: 0.85rem;
    }}
    .findings-table td {{
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid #e9ecef;
      font-size: 0.85rem;
      vertical-align: top;
    }}
    .findings-table tr:last-child td {{
      border-bottom: none;
    }}
    .findings-table tr:hover {{
      background: #f1f3f5;
    }}
    .severity-badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 3px;
      color: #fff;
      font-size: 0.8rem;
      font-weight: 600;
    }}
    .suppressed {{
      opacity: 0.6;
      text-decoration: line-through;
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

  <table class="summary-table">
    <tr><td>Scan ID</td><td>{html_lib.escape(report.scan_id)}</td></tr>
    <tr><td>Path</td><td>{html_lib.escape(report.artifact_path)}</td></tr>
    <tr><td>Timestamp</td><td>{html_lib.escape(report.scan_timestamp.isoformat())}</td></tr>
    <tr><td>Version</td><td>{html_lib.escape(report.scanner_version)}</td></tr>
    <tr>
      <td>Gate Decision</td>
      <td><span class="gate-badge" style="background:{gate_color}">{html_lib.escape(gate.value)}</span></td>
    </tr>
    <tr><td>Total Findings</td><td>{report.summary.total_findings}</td></tr>
    <tr><td>Blocking</td><td>{report.summary.blocking_findings}</td></tr>
    <tr><td>Warnings</td><td>{report.summary.warning_findings}</td></tr>
    <tr><td>Info</td><td>{report.summary.info_findings}</td></tr>
  </table>

  <h2>Findings</h2>
  {_render_findings_section(report, findings_rows)}
{errors_section}
</body>
</html>"""


def _render_findings_section(report: ScanReport, findings_rows: str) -> str:
    """Render the findings section — table or 'no findings' message."""
    if not report.findings:
        return '  <p class="no-findings">No findings detected.</p>'

    return f"""<table class="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Risk ID</th>
        <th>Title</th>
        <th>File</th>
        <th>Line</th>
        <th>Gate</th>
      </tr>
    </thead>
    <tbody>
{findings_rows}
    </tbody>
  </table>"""


def _render_finding_row(finding: ScanFinding) -> str:
    """Render a single finding as an HTML table row."""
    sev_color = _SEVERITY_COLOR.get(finding.severity_label, "#333")
    line_str = str(finding.location.line) if finding.location.line else "&mdash;"

    suppressed_class = ' class="suppressed"' if finding.false_positive else ""

    return f"""      <tr{suppressed_class}>
        <td><span class="severity-badge" style="background:{sev_color}">{html_lib.escape(finding.severity_label.value)} (S{finding.severity_score})</span></td>
        <td>{html_lib.escape(finding.id)}</td>
        <td>{html_lib.escape(finding.title)}</td>
        <td>{html_lib.escape(finding.artifact_path)}</td>
        <td>{line_str}</td>
        <td>{html_lib.escape(finding.gate_action.value)}</td>
      </tr>"""
