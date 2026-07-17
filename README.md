# Code Security Analysis Platform 🔐

A self-hosted platform that accepts source code and returns detailed security findings with OWASP-aligned severity ratings and remediation guidance.

---

## Features

| Feature | Details |
|---|---|
| **Multi-language support** | Python, C, C++, JavaScript, TypeScript, Java, Go, Ruby, PHP |
| **Analysis engines** | [Bandit](https://bandit.readthedocs.io/) (Python), [Semgrep](https://semgrep.dev/) (all), Custom OWASP rules |
| **Severity levels** | Critical · High · Medium · Low · Informational |
| **Security Score** | 0–100 score deducted per finding |
| **Export formats** | JSON · HTML · PDF |
| **Web UI** | Dashboard, scan form, report viewer |
| **REST API** | `POST /analyze` · `GET /reports/{id}` |
| **API Key Auth** | `X-API-Key` header (disabled by default in dev) |
| **CI/CD integration** | GitHub Actions workflow auto-scans every PR |
| **GitHub Webhook** | `POST /webhook/github` posts findings as PR review comments |

---

## Quick Start (Docker)

```bash
# Clone and start
git clone https://github.com/shivjanamsonkar/RND.git
cd RND
docker-compose up --build

# Open the web UI
open http://localhost:8000
```

---

## REST API

### `POST /analyze`

Submit source code for analysis.

**Form fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | file upload | one of | Source file to scan |
| `code` | string | one of | Raw source code |
| `language` | string | no | Override language detection |
| `filename` | string | no | Filename for display / language detection |

**Example (curl):**

```bash
# Upload a file
curl -X POST http://localhost:8000/analyze \
  -F "file=@listener.c"

# Paste code
curl -X POST http://localhost:8000/analyze \
  -F "code=$(cat listener.c)" \
  -F "language=c" \
  -F "filename=listener.c"
```

**Response (JSON):**

```json
{
  "id": "3fa85f64-...",
  "created_at": "2024-01-01T12:00:00",
  "language": "c",
  "filename": "listener.c",
  "security_score": 52,
  "total_findings": 5,
  "critical": 1,
  "high": 2,
  "medium": 1,
  "low": 0,
  "informational": 1,
  "findings": [
    {
      "file": "listener.c",
      "line": 41,
      "severity": "Critical",
      "rule_id": "CUSTOM-015",
      "description": "Socket accept() with no visible authentication check.",
      "remediation": "Implement authentication before processing data from accepted connections.",
      "code_snippet": "if((c = accept(s,(struct sockaddr *)&clientAddress,&addrlen)) == -1)",
      "source_tool": "custom"
    }
  ]
}
```

### `GET /reports`

List all scans (summary).

### `GET /reports/{id}`

Full report as JSON.

### `GET /reports/{id}/html`

Full report as styled HTML.

### `GET /reports/{id}/pdf`

Full report as PDF (requires `weasyprint`; falls back to HTML).

---

## Authentication

By default, authentication is **disabled** (dev mode).

To enable, set the `SECURITY_API_KEYS` environment variable to a comma-separated list of keys:

```bash
SECURITY_API_KEYS=my-secret-key-1,my-secret-key-2 docker-compose up
```

Then pass the key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: my-secret-key-1" http://localhost:8000/reports
```

---

## CI/CD Integration

### Automatic PR scanning (GitHub Actions)

The workflow in `.github/workflows/security-scan.yml` runs on every pull request and posts findings as a PR comment. No configuration needed.

Optional: add a `SEMGREP_APP_TOKEN` secret in your repo settings to enable Semgrep's managed rules.

### GitHub Webhook

1. Go to **Settings → Webhooks → Add webhook** in your repository.
2. Set **Payload URL** to `https://your-server/webhook/github`.
3. Set **Content type** to `application/json`.
4. Set **Secret** and add it as `GITHUB_WEBHOOK_SECRET` in your environment.
5. Select **Pull request** events only.
6. Set `GITHUB_TOKEN` in your environment (PAT with `repo` scope).

---

## Local Development (without Docker)

```bash
cd backend
pip install -r requirements.txt

# Run the API server
uvicorn app.main:app --reload --port 8000

# Open
open http://localhost:8000
```

---

## Project Structure

```
.
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app entry-point
│   │   ├── api/
│   │   │   ├── analyze.py           # POST /analyze
│   │   │   ├── reports.py           # GET /reports
│   │   │   └── webhook.py           # POST /webhook/github
│   │   ├── analyzers/
│   │   │   ├── bandit_analyzer.py   # Python static analysis
│   │   │   ├── semgrep_analyzer.py  # Multi-language analysis
│   │   │   └── custom_rules.py      # OWASP regex rules
│   │   ├── models/
│   │   │   ├── finding.py           # Finding schema
│   │   │   └── report.py            # Report schema
│   │   └── services/
│   │       ├── analysis_service.py  # Orchestration
│   │       ├── report_service.py    # Storage + HTML/PDF generation
│   │       └── auth_service.py      # API key middleware
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html                   # Scan dashboard
│   ├── report.html                  # Report viewer
│   └── static/
│       ├── css/style.css
│       └── js/
│           ├── app.js               # Dashboard logic
│           └── report.js            # Report viewer logic
├── .github/
│   └── workflows/
│       └── security-scan.yml        # PR auto-scan workflow
├── docker-compose.yml
└── listener.c                       # Original R&D C listener
```

---

## Original R&D — C Listener

The original `listener.c` is a simple TCP listener intended for POS devices.

```bash
gcc listener.c -o listener
./listener
# Then: telnet 127.0.0.1 8080
```

> **Note:** Running `POST /analyze` with `listener.c` as input will produce several real security findings as a built-in demo.
