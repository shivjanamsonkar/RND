"""
Semgrep analyzer — runs semgrep with the auto ruleset (OWASP / security packs).
Works on any language that semgrep supports.
"""
import json
import subprocess
import tempfile
import os

from app.analyzers.base import BaseAnalyzer
from app.models.finding import Finding, Severity

SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

LANGUAGE_EXTENSION: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
    "go": ".go",
    "ruby": ".rb",
    "php": ".php",
}


def _get_remediation(metadata: dict) -> str:
    """Extract a human-readable remediation hint from semgrep metadata."""
    # semgrep metadata can contain 'fix', 'message', or 'references'
    fix = metadata.get("fix") or metadata.get("fix_regex", {}).get("replacement")
    if fix:
        return f"Suggested fix: {fix}"
    refs = metadata.get("references", [])
    if refs:
        return f"See: {refs[0]}"
    cwe = metadata.get("cwe", "")
    owasp = metadata.get("owasp", "")
    if cwe or owasp:
        return f"Refer to {cwe or ''} {owasp or ''}. Apply secure coding practices.".strip()
    return "Review the flagged code and apply secure coding practices."


class SemgrepAnalyzer(BaseAnalyzer):
    def analyze(self, code: str, filepath: str, language: str) -> list[Finding]:
        ext = LANGUAGE_EXTENSION.get(language.lower(), ".txt")

        with tempfile.NamedTemporaryFile(suffix=ext, delete=False, mode="w") as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    tmp_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            raw = result.stdout.strip()
            if not raw:
                return []
            data = json.loads(raw)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            return []
        finally:
            os.unlink(tmp_path)

        findings: list[Finding] = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            raw_sev = r.get("extra", {}).get("severity", "WARNING")
            severity = SEMGREP_SEVERITY_MAP.get(raw_sev.upper(), Severity.MEDIUM)

            # Upgrade to CRITICAL if metadata marks it as critical
            if meta.get("confidence", "").upper() == "HIGH" and severity == Severity.HIGH:
                severity = Severity.CRITICAL

            lines_obj = r.get("extra", {}).get("lines", "")
            snippet = lines_obj.strip() if isinstance(lines_obj, str) else ""

            findings.append(
                Finding(
                    file=filepath,
                    line=r.get("start", {}).get("line"),
                    column=r.get("start", {}).get("col"),
                    severity=severity,
                    rule_id=r.get("check_id", "semgrep.unknown"),
                    description=r.get("extra", {}).get("message", "Security issue detected."),
                    remediation=_get_remediation(meta),
                    code_snippet=snippet,
                    source_tool="semgrep",
                )
            )
        return findings
