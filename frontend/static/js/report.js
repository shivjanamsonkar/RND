/* ── Report detail page ─────────────────────────────────────────────────── */
const API = '';


function scoreClass(s) {
  return s >= 80 ? 'score-high' : s >= 50 ? 'score-medium' : 'score-low';
}

function buildReport(r) {
  const scoreColor = r.security_score >= 80 ? '#27ae60' : r.security_score >= 50 ? '#d4ac0d' : '#c0392b';

  const findingRows = r.findings.map((f) => {
    const snippet = f.code_snippet
      ? `<pre class="snippet">${esc(f.code_snippet)}</pre>` : '';
    return `<tr>
      <td><span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td><code>${esc(f.rule_id)}</code></td>
      <td>${f.line ?? '—'}</td>
      <td>${esc(f.description)}${snippet}</td>
      <td>${esc(f.remediation)}</td>
      <td><code>${esc(f.source_tool)}</code></td>
    </tr>`;
  }).join('');

  const noFindings = r.total_findings === 0
    ? '<tr><td colspan="6" style="text-align:center;color:#27ae60;padding:20px;">✅ No security issues found!</td></tr>'
    : '';

  return `
    <div class="card">
      <h2>🔐 Security Report</h2>
      <p class="report-meta">
        File: <strong>${esc(r.filename)}</strong> &nbsp;|&nbsp;
        Language: <strong>${esc(r.language)}</strong> &nbsp;|&nbsp;
        Scanned: <strong>${new Date(r.created_at).toLocaleString()}</strong><br>
        Report ID: <code>${esc(r.id)}</code>
      </p>

      <div class="export-btns">
        <a class="btn-sm" href="${API}/reports/${r.id}/html" target="_blank">📄 Download HTML</a>
        <a class="btn-sm" href="${API}/reports/${r.id}/pdf"  target="_blank">📑 Download PDF</a>
        <a class="btn-sm" href="/">← New Scan</a>
      </div>

      <div class="score-cards">
        <div class="score-card">
          <div class="num" style="color:${scoreColor}">${r.security_score}</div>
          <div class="lbl">Security Score</div>
        </div>
        <div class="score-card">
          <div class="num" style="color:#c0392b">${r.critical}</div>
          <div class="lbl">Critical</div>
        </div>
        <div class="score-card">
          <div class="num" style="color:#e67e22">${r.high}</div>
          <div class="lbl">High</div>
        </div>
        <div class="score-card">
          <div class="num" style="color:#d4ac0d">${r.medium}</div>
          <div class="lbl">Medium</div>
        </div>
        <div class="score-card">
          <div class="num" style="color:#27ae60">${r.low}</div>
          <div class="lbl">Low</div>
        </div>
        <div class="score-card">
          <div class="num" style="color:#2980b9">${r.informational}</div>
          <div class="lbl">Info</div>
        </div>
        <div class="score-card">
          <div class="num">${r.total_findings}</div>
          <div class="lbl">Total</div>
        </div>
      </div>

      <table class="findings-table">
        <thead>
          <tr>
            <th>Severity</th><th>Rule ID</th><th>Line</th>
            <th>Description &amp; Snippet</th><th>Remediation</th><th>Tool</th>
          </tr>
        </thead>
        <tbody>${findingRows}${noFindings}</tbody>
      </table>
    </div>`;
}

async function loadReport() {
  const wrap = document.getElementById('report-wrap');
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');
  if (!id) {
    wrap.innerHTML = '<p class="loading" style="color:#c0392b">No report ID specified in URL.</p>';
    return;
  }
  try {
    const resp = await fetch(`${API}/reports/${id}`);
    if (!resp.ok) throw new Error('Report not found.');
    const report = await resp.json();
    document.title = `Security Report — ${report.filename}`;
    wrap.innerHTML = buildReport(report);
  } catch (err) {
    wrap.innerHTML = `<p class="loading" style="color:#c0392b">❌ ${err.message}</p>`;
  }
}

loadReport();
