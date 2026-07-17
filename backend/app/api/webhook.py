"""
POST /webhook/github  — GitHub webhook endpoint.

When a pull request is opened/synchronised, this endpoint:
1. Fetches the changed .py/.c/.js/etc. files via the GitHub API.
2. Runs security analysis on each file.
3. Posts a combined review comment on the PR.

Environment variables required:
  GITHUB_TOKEN       — Personal Access Token with repo scope
  GITHUB_WEBHOOK_SECRET (optional) — HMAC secret set in the GitHub webhook settings
"""
import hashlib
import hmac
import os

import httpx
from fastapi import APIRouter, Header, HTTPException, Request, status

from app.services.analysis_service import analyze_code, EXTENSION_TO_LANGUAGE
from app.services.report_service import save_report, generate_html

router = APIRouter()

_GH_TOKEN = os.getenv("GITHUB_TOKEN", "")
_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

SUPPORTED_EXTENSIONS = set(EXTENSION_TO_LANGUAGE.keys())


def _verify_signature(body: bytes, signature: str | None) -> None:
    """Verify the X-Hub-Signature-256 header if a secret is configured."""
    if not _WEBHOOK_SECRET:
        return
    if not signature:
        raise HTTPException(status_code=403, detail="Missing X-Hub-Signature-256 header.")
    expected = "sha256=" + hmac.new(
        _WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=403, detail="Invalid webhook signature.")


@router.post(
    "/webhook/github",
    summary="GitHub webhook — auto-scan PRs",
    status_code=status.HTTP_202_ACCEPTED,
)
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    body = await request.body()
    _verify_signature(body, x_hub_signature_256)

    if x_github_event != "pull_request":
        return {"detail": "Event ignored."}

    payload = await request.json()
    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return {"detail": "PR action ignored."}

    pr = payload["pull_request"]
    repo_full = payload["repository"]["full_name"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]

    if not _GH_TOKEN:
        return {"detail": "GITHUB_TOKEN not set — skipping scan."}

    headers = {
        "Authorization": f"token {_GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Fetch changed files
    async with httpx.AsyncClient(headers=headers, timeout=30) as client:
        files_resp = await client.get(
            f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/files"
        )
        files_resp.raise_for_status()
        changed_files = files_resp.json()

        comment_lines: list[str] = [
            "## 🔐 Automated Security Scan\n",
            f"Scan triggered by commit `{head_sha[:8]}`.\n",
        ]
        total_critical = total_high = 0

        for file_info in changed_files:
            path: str = file_info["filename"]
            ext = os.path.splitext(path)[1].lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue

            # Download raw file content
            raw_url = file_info.get("raw_url") or (
                f"https://raw.githubusercontent.com/{repo_full}/{head_sha}/{path}"
            )
            try:
                content_resp = await client.get(raw_url)
                content_resp.raise_for_status()
                code = content_resp.text
            except Exception:
                continue

            report = analyze_code(code, path)
            save_report(report)
            total_critical += report.critical
            total_high += report.high

            if report.total_findings == 0:
                comment_lines.append(f"### `{path}` — ✅ No issues found\n")
            else:
                comment_lines.append(
                    f"### `{path}` — Score: **{report.security_score}/100** "
                    f"({report.critical} Critical / {report.high} High / "
                    f"{report.medium} Medium / {report.low} Low)\n"
                )
                comment_lines.append("| Severity | Rule | Line | Description |\n")
                comment_lines.append("|----------|------|------|-------------|\n")
                for f in report.findings[:20]:  # cap at 20 rows per file
                    comment_lines.append(
                        f"| {f.severity} | `{f.rule_id}` | {f.line or '—'} | {f.description} |\n"
                    )
                if report.total_findings > 20:
                    comment_lines.append(
                        f"> … and {report.total_findings - 20} more findings.\n"
                    )

        comment_lines.append("\n---\n")
        if total_critical > 0:
            comment_lines.append(
                f"⛔ **{total_critical} Critical** finding(s) detected — merge blocked.\n"
            )
        elif total_high > 0:
            comment_lines.append(
                f"⚠️ **{total_high} High** severity finding(s) — please review before merging.\n"
            )
        else:
            comment_lines.append("✅ No Critical or High severity issues found.\n")

        comment_body = "".join(comment_lines)

        # Post the review comment
        await client.post(
            f"https://api.github.com/repos/{repo_full}/issues/{pr_number}/comments",
            json={"body": comment_body},
        )

    return {"detail": "Scan complete.", "critical": total_critical, "high": total_high}
