"""
Report service — in-memory report store + HTML/JSON/PDF generation.

In production, replace the in-memory dict with a PostgreSQL-backed store.
"""
import json
import os
from datetime import datetime, timezone

from app.models.report import Report

# ── In-memory store (keyed by report ID) ──────────────────────────────────────
_store: dict[str, Report] = {}


def save_report(report: Report) -> None:
    _store[report.id] = report


def get_report(report_id: str) -> Report | None:
    return _store.get(report_id)


def list_reports() -> list[dict]:
    return [
        {
            "id": r.id,
            "filename": r.filename,
            "language": r.language,
            "security_score": r.security_score,
            "total_findings": r.total_findings,
            "created_at": r.created_at.isoformat(),
        }
        for r in sorted(_store.values(), key=lambda x: x.created_at, reverse=True)
    ]


# ── HTML Report ───────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#27ae60",
    "Informational": "#2980b9",
}

_SCORE_COLORS = {
    range(80, 101): "#27ae60",
    range(50, 80): "#f1c40f",
    range(0, 50): "#c0392b",
}


def _score_color(score: int) -> str:
    for r, color in _SCORE_COLORS.items():
        if score in r:
            return color
    return "#999"


def _finding_rows(report: Report) -> str:
    rows = []
    for f in report.findings:
        color = _SEVERITY_COLORS.get(f.severity, "#999")
        snippet = f.code_snippet or ""
        snippet_html = (
            f'<pre class="snippet">{_esc(snippet)}</pre>' if snippet else ""
        )
        rows.append(
            f"""
            <tr>
              <td><span class="badge" style="background:{color}">{_esc(f.severity)}</span></td>
              <td>{_esc(f.rule_id)}</td>
              <td>{f.line or "—"}</td>
              <td>{_esc(f.description)}{snippet_html}</td>
              <td>{_esc(f.remediation)}</td>
              <td><code>{_esc(f.source_tool)}</code></td>
            </tr>"""
        )
    return "\n".join(rows)


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html(report: Report) -> str:
    score_color = _score_color(report.security_score)
    rows = _finding_rows(report)
    no_findings_msg = (
        '<tr><td colspan="6" style="text-align:center;color:#27ae60;padding:20px;">'
        "✅ No security issues found!</td></tr>"
        if not report.findings
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {_esc(report.filename)}</title>
<style>
  :root {{--accent:#2c3e50}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#f4f6f9;color:#333;padding:24px}}
  h1{{color:var(--accent);margin-bottom:4px}}
  .meta{{color:#666;font-size:.9rem;margin-bottom:24px}}
  .cards{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
  .card{{background:#fff;border-radius:10px;padding:20px 28px;box-shadow:0 1px 4px rgba(0,0,0,.1);min-width:140px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{font-size:.8rem;color:#888;text-transform:uppercase;letter-spacing:.05em}}
  .score-ring{{font-size:2.8rem;font-weight:900;color:{score_color}}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
  th{{background:var(--accent);color:#fff;padding:12px 14px;text-align:left;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:12px 14px;border-bottom:1px solid #eee;vertical-align:top;font-size:.9rem}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#f9f9f9}}
  .badge{{display:inline-block;color:#fff;border-radius:4px;padding:2px 10px;font-size:.8rem;font-weight:600}}
  pre.snippet{{background:#f4f6f9;border-left:3px solid #ccc;padding:8px 10px;margin-top:6px;font-size:.8rem;white-space:pre-wrap;word-break:break-word;border-radius:4px}}
  footer{{text-align:center;margin-top:32px;color:#aaa;font-size:.8rem}}
</style>
</head>
<body>
<h1>🔐 Code Security Report</h1>
<p class="meta">File: <strong>{_esc(report.filename)}</strong> &nbsp;|&nbsp;
Language: <strong>{_esc(report.language.title())}</strong> &nbsp;|&nbsp;
Scanned: <strong>{report.created_at.strftime('%Y-%m-%d %H:%M UTC')}</strong> &nbsp;|&nbsp;
Report ID: <code>{_esc(report.id)}</code></p>

<div class="cards">
  <div class="card">
    <div class="score-ring">{report.security_score}</div>
    <div class="lbl">Security Score</div>
  </div>
  <div class="card">
    <div class="num" style="color:#c0392b">{report.critical}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="card">
    <div class="num" style="color:#e67e22">{report.high}</div>
    <div class="lbl">High</div>
  </div>
  <div class="card">
    <div class="num" style="color:#d4ac0d">{report.medium}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="card">
    <div class="num" style="color:#27ae60">{report.low}</div>
    <div class="lbl">Low</div>
  </div>
  <div class="card">
    <div class="num" style="color:#2980b9">{report.informational}</div>
    <div class="lbl">Info</div>
  </div>
  <div class="card">
    <div class="num">{report.total_findings}</div>
    <div class="lbl">Total Findings</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>Severity</th><th>Rule ID</th><th>Line</th>
      <th>Description &amp; Snippet</th><th>Remediation</th><th>Tool</th>
    </tr>
  </thead>
  <tbody>
    {rows}
    {no_findings_msg}
  </tbody>
</table>

<footer>Generated by Code Security Analysis Platform &copy; {datetime.now(timezone.utc).year}</footer>
</body>
</html>"""


# ── PDF Report ────────────────────────────────────────────────────────────────

def generate_pdf(report: Report) -> bytes:
    """
    Convert the HTML report to PDF using weasyprint (if installed),
    otherwise return the raw HTML bytes as a fallback.
    """
    html_content = generate_html(report)
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html_content).write_pdf()
    except ImportError:
        # weasyprint not available — return HTML bytes
        return html_content.encode()
