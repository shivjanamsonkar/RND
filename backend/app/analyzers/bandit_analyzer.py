"""
Bandit analyzer — runs Python static analysis via bandit CLI.
Only active when language == "python".
"""
import json
import subprocess
import tempfile
import os

from app.analyzers.base import BaseAnalyzer
from app.models.finding import Finding, Severity

BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

BANDIT_CONFIDENCE_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

REMEDIATION_HINTS: dict[str, str] = {
    "B101": "Avoid assert statements in production code; use proper validation.",
    "B102": "Use of exec() is dangerous; avoid executing arbitrary strings.",
    "B103": "Setting file permissions too broadly; use restrictive permissions (e.g., 0o600).",
    "B104": "Binding to all interfaces (0.0.0.0) exposes the service externally.",
    "B105": "Hardcoded password detected; use environment variables or secrets managers.",
    "B106": "Hardcoded password in function call; use environment variables.",
    "B107": "Hardcoded password argument; use environment variables.",
    "B108": "Insecure temp file usage; use tempfile module with secure defaults.",
    "B110": "Try/except pass silences errors; log or handle exceptions explicitly.",
    "B112": "Try/except continue silences errors; handle exceptions explicitly.",
    "B201": "Flask app running in debug mode exposes sensitive info; disable in production.",
    "B301": "Pickle deserialization is unsafe; prefer JSON or other safe formats.",
    "B302": "marshal.loads is unsafe; prefer safer serialization formats.",
    "B303": "MD5/SHA1 are weak hash algorithms; use SHA-256 or stronger.",
    "B304": "Insecure cipher usage; use AES-GCM or other authenticated encryption.",
    "B305": "Insecure cipher mode (ECB); use GCM or CBC with random IV.",
    "B306": "mktemp is insecure; use tempfile.mkstemp instead.",
    "B307": "eval() is dangerous; avoid executing untrusted strings.",
    "B310": "urllib URL open with user-supplied input; validate and sanitize URLs.",
    "B311": "random module is not cryptographically secure; use secrets module.",
    "B312": "telnetlib is insecure; use SSH instead.",
    "B313": "xml.etree parsing may be vulnerable to XXE; use defusedxml.",
    "B320": "xml.etree.ElementTree parsing is vulnerable to XXE; use defusedxml.",
    "B321": "FTP is insecure; use SFTP instead.",
    "B322": "input() in Python 2 is unsafe; use raw_input() or upgrade to Python 3.",
    "B323": "Unverified SSL context; enable certificate verification.",
    "B324": "hashlib using weak algorithm; use SHA-256 or stronger.",
    "B325": "os.tempnam is insecure; use tempfile.mkstemp.",
    "B401": "Importing telnetlib (insecure); use paramiko/SSH instead.",
    "B402": "Importing ftplib (insecure); use SFTP instead.",
    "B411": "Importing xmlrpclib; validate input carefully to avoid SSRF/XXE.",
    "B501": "SSL certificate verification disabled; enable verification.",
    "B502": "ssl.wrap_socket with no_sslv2=False; enforce TLS 1.2+.",
    "B503": "SSL use_openssl_cafile without validation; verify certificates.",
    "B504": "ssl.wrap_socket is deprecated; use ssl.SSLContext.",
    "B505": "Weak RSA/DSA key size; use at least 2048-bit keys.",
    "B506": "yaml.load without Loader is unsafe; use yaml.safe_load.",
    "B507": "Paramiko host key auto-add is insecure; use known_hosts verification.",
    "B601": "Shell injection risk via paramiko exec_command; sanitize inputs.",
    "B602": "subprocess with shell=True and user input; use list form instead.",
    "B603": "subprocess without shell=True is safer; validate all arguments.",
    "B604": "Function call with shell=True; prefer list-form subprocess calls.",
    "B605": "os.system with user input; use subprocess with a list of args.",
    "B606": "os.spawn* with user input; use subprocess instead.",
    "B607": "Partial executable path in subprocess; use the full absolute path.",
    "B608": "Possible SQL injection; use parameterized queries.",
    "B609": "Wildcard injection via Linux commands; sanitize filenames.",
    "B610": "Django extra() with user input is vulnerable to SQL injection.",
    "B611": "Django RawSQL() with user input is vulnerable to SQL injection.",
    "B701": "Jinja2 autoescape disabled; enable autoescape to prevent XSS.",
    "B702": "Mako templates without autoescaping; escape user input explicitly.",
    "B703": "Django mark_safe with user content; avoid or sanitize before use.",
}

DEFAULT_REMEDIATION = (
    "Review the flagged code and apply secure coding best practices. "
    "Consult the Bandit documentation for rule-specific guidance."
)


def _map_severity(bandit_severity: str, bandit_confidence: str) -> Severity:
    """Upgrade severity when both severity and confidence are HIGH."""
    sev = BANDIT_SEVERITY_MAP.get(bandit_severity.upper(), Severity.LOW)
    conf = BANDIT_CONFIDENCE_MAP.get(bandit_confidence.upper(), Severity.LOW)
    if sev == Severity.HIGH and conf == Severity.HIGH:
        return Severity.CRITICAL
    return sev


class BanditAnalyzer(BaseAnalyzer):
    def analyze(self, code: str, filepath: str, language: str) -> list[Finding]:
        if language.lower() != "python":
            return []

        # Write code to a temp .py file so bandit can process it
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", tmp_path],
                capture_output=True,
                text=True,
                timeout=60,
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
        for issue in data.get("results", []):
            rule_id = issue.get("test_id", "UNKNOWN")
            snippet = issue.get("code", "").strip()
            line = issue.get("line_number")
            col = issue.get("col_offset")
            severity = _map_severity(
                issue.get("issue_severity", "LOW"),
                issue.get("issue_confidence", "LOW"),
            )
            findings.append(
                Finding(
                    file=filepath,
                    line=line,
                    column=col,
                    severity=severity,
                    rule_id=rule_id,
                    description=issue.get("issue_text", "Security issue detected."),
                    remediation=REMEDIATION_HINTS.get(rule_id, DEFAULT_REMEDIATION),
                    code_snippet=snippet,
                    source_tool="bandit",
                )
            )
        return findings
