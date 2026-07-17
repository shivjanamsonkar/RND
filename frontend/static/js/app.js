/* ── Helpers ─────────────────────────────────────────────────────────────── */
const $ = (id) => document.getElementById(id);
const API = '';  // same origin

/* ── Tab switching ───────────────────────────────────────────────────────── */
function switchTab(tab) {
  $('tab-file').classList.toggle('hidden', tab !== 'file');
  $('tab-paste').classList.toggle('hidden', tab !== 'paste');
  document.querySelectorAll('.tab').forEach((el, i) => {
    el.classList.toggle('active', (i === 0 && tab === 'file') || (i === 1 && tab === 'paste'));
  });
}

/* ── Drag-and-drop ───────────────────────────────────────────────────────── */
const dropZone = $('drop-zone');
const fileInput = $('file-input');

dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) {
    $('drop-text').textContent = `📄 ${fileInput.files[0].name}`;
  }
});
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const dt = e.dataTransfer;
  if (dt.files[0]) {
    fileInput.files = dt.files;
    $('drop-text').textContent = `📄 ${dt.files[0].name}`;
  }
});

/* ── Form submit ─────────────────────────────────────────────────────────── */
$('scan-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('scan-btn');
  const statusEl = $('scan-status');
  const apiKey = $('api-key-input').value.trim();

  btn.disabled = true;
  btn.textContent = '⏳ Scanning…';
  statusEl.className = 'status info';
  statusEl.textContent = 'Submitting code for analysis…';
  statusEl.classList.remove('hidden');

  try {
    const isFile = !$('tab-file').classList.contains('hidden');
    const fd = new FormData();

    if (isFile) {
      const file = fileInput.files[0];
      if (!file) throw new Error('Please select a file to upload.');
      fd.append('file', file);
    } else {
      const code = $('code-textarea').value.trim();
      if (!code) throw new Error('Please paste some code to analyze.');
      fd.append('code', code);
      const lang = $('lang-select').value;
      if (lang) fd.append('language', lang);
      const fname = $('fname-input').value.trim() || 'pasted_code.txt';
      fd.append('filename', fname);
    }

    const headers = {};
    if (apiKey) headers['X-API-Key'] = apiKey;

    const resp = await fetch(`${API}/analyze`, { method: 'POST', headers, body: fd });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: resp.statusText }));
      throw new Error(err.detail || 'Analysis failed.');
    }
    const report = await resp.json();

    statusEl.className = 'status success';
    statusEl.innerHTML =
      `✅ Scan complete — <strong>${report.total_findings}</strong> finding(s) ` +
      `| Score: <strong>${report.security_score}/100</strong>. ` +
      `<a href="/report?id=${report.id}">View full report →</a>`;

    loadHistory();
  } catch (err) {
    statusEl.className = 'status error';
    statusEl.textContent = `❌ ${err.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = '🔍 Scan Now';
  }
});

/* ── History ──────────────────────────────────────────────────────────────── */
async function loadHistory() {
  const wrap = $('history-table-wrap');
  wrap.innerHTML = '<p class="loading">Loading…</p>';
  try {
    const resp = await fetch(`${API}/reports`);
    if (!resp.ok) throw new Error('Could not load history.');
    const reports = await resp.json();

    if (!reports.length) {
      wrap.innerHTML = '<p class="loading">No scans yet. Submit some code above!</p>';
      return;
    }

    const rows = reports.map((r) => {
      const score = r.security_score;
      const cls = score >= 80 ? 'score-high' : score >= 50 ? 'score-medium' : 'score-low';
      return `<tr>
        <td><a href="/report?id=${r.id}">${esc(r.filename)}</a></td>
        <td>${esc(r.language)}</td>
        <td><span class="score-badge ${cls}">${score}</span></td>
        <td>${r.total_findings}</td>
        <td>${new Date(r.created_at).toLocaleString()}</td>
        <td>
          <a href="/report?id=${r.id}">View</a> &nbsp;
          <a href="${API}/reports/${r.id}/html" target="_blank">HTML</a> &nbsp;
          <a href="${API}/reports/${r.id}/pdf" target="_blank">PDF</a>
        </td>
      </tr>`;
    }).join('');

    wrap.innerHTML = `
      <table class="history-table">
        <thead><tr>
          <th>File</th><th>Language</th><th>Score</th>
          <th>Findings</th><th>Scanned At</th><th>Export</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  } catch (err) {
    wrap.innerHTML = `<p class="loading" style="color:#c0392b">${esc(err.message)}</p>`;
  }
}

function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

loadHistory();
