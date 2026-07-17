"""
Custom OWASP-Top-10-inspired rules that work via regex/AST pattern matching.
These complement Bandit and Semgrep with language-agnostic heuristics.
"""
import re
from app.analyzers.base import BaseAnalyzer
from app.models.finding import Finding, Severity

# Each rule is: (rule_id, severity, pattern_flags, regex, description, remediation)
CUSTOM_RULES: list[tuple] = [
    # ── Hardcoded Credentials ──────────────────────────────────────────────────
    (
        "CUSTOM-001",
        Severity.CRITICAL,
        re.IGNORECASE,
        r'(password|passwd|secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{4,}["\']',
        "Hardcoded credential detected.",
        "Remove hardcoded credentials and load them from environment variables "
        "or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
    ),
    # ── SQL Injection ──────────────────────────────────────────────────────────
    (
        "CUSTOM-002",
        Severity.CRITICAL,
        re.IGNORECASE,
        r'(execute|query|cursor\.execute)\s*\(\s*[f"\'].*?(SELECT|INSERT|UPDATE|DELETE)',
        "Possible SQL injection via string formatting in a database query.",
        "Use parameterized queries / prepared statements. Never concatenate or "
        "format user input directly into SQL strings.",
    ),
    # ── Command Injection ─────────────────────────────────────────────────────
    (
        "CUSTOM-003",
        Severity.CRITICAL,
        re.IGNORECASE,
        r'(os\.system|os\.popen|subprocess\.(call|run|Popen))\s*\([^)]*\+',
        "Possible command injection: user input concatenated into shell command.",
        "Never concatenate user-controlled input into shell commands. Use "
        "subprocess with a list of arguments and shell=False.",
    ),
    # ── Path Traversal ────────────────────────────────────────────────────────
    (
        "CUSTOM-004",
        Severity.HIGH,
        re.IGNORECASE,
        r'open\s*\(\s*(request\.|input|argv|params|body)',
        "Possible path traversal: file open with user-supplied path.",
        "Validate and sanitize file paths. Use os.path.abspath and ensure the "
        "resolved path is within an allowed base directory.",
    ),
    # ── Insecure Deserialization ──────────────────────────────────────────────
    (
        "CUSTOM-005",
        Severity.HIGH,
        re.IGNORECASE,
        r'\bpickle\.(loads?|Unpickler)',
        "Insecure deserialization via pickle.",
        "Avoid deserializing untrusted data with pickle. Prefer JSON or other "
        "safe formats. If pickle is required, use HMAC signatures to verify integrity.",
    ),
    # ── XXE via XML Parsing ───────────────────────────────────────────────────
    (
        "CUSTOM-006",
        Severity.HIGH,
        re.IGNORECASE,
        r'(xml\.etree|minidom|lxml\.etree)\.parse',
        "XML parsing without XXE protection.",
        "Use defusedxml to parse XML, which disables external entity processing "
        "by default and prevents XXE attacks.",
    ),
    # ── Weak Crypto ───────────────────────────────────────────────────────────
    (
        "CUSTOM-007",
        Severity.MEDIUM,
        re.IGNORECASE,
        r'hashlib\.(md5|sha1)\s*\(',
        "Use of weak cryptographic hash (MD5 or SHA-1).",
        "Replace MD5/SHA1 with SHA-256 or SHA-3 for security-sensitive operations. "
        "For passwords, use bcrypt, scrypt, or argon2.",
    ),
    # ── Insecure Random ──────────────────────────────────────────────────────
    (
        "CUSTOM-008",
        Severity.MEDIUM,
        re.IGNORECASE,
        r'\brandom\.(random|randint|choice|choices|shuffle)',
        "Use of non-cryptographic random number generator.",
        "Use the `secrets` module for security-sensitive random values such as "
        "tokens, nonces, or OTPs.",
    ),
    # ── Debug / Info Disclosure ──────────────────────────────────────────────
    (
        "CUSTOM-009",
        Severity.LOW,
        re.IGNORECASE,
        r'(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)',
        "Debug mode enabled, which may expose stack traces and configuration.",
        "Set DEBUG=False in production. Use environment-based configuration to "
        "control debug flags.",
    ),
    # ── Hardcoded IP / Localhost Binding ────────────────────────────────────
    (
        "CUSTOM-010",
        Severity.LOW,
        0,
        r'INADDR_ANY|0\.0\.0\.0',
        "Server bound to all network interfaces (INADDR_ANY / 0.0.0.0).",
        "Bind only to the required interface. For internal services, bind to "
        "127.0.0.1 or a specific private IP to reduce exposure.",
    ),
    # ── C/C++ gets() buffer overflow ────────────────────────────────────────
    (
        "CUSTOM-011",
        Severity.CRITICAL,
        0,
        r'\bgets\s*\(',
        "Use of gets() which does not perform bounds checking — buffer overflow risk.",
        "Replace gets() with fgets(buf, sizeof(buf), stdin) which limits input size.",
    ),
    # ── C/C++ strcpy/strcat without bounds ──────────────────────────────────
    (
        "CUSTOM-012",
        Severity.HIGH,
        0,
        r'\b(strcpy|strcat)\s*\(',
        "Use of strcpy/strcat without bounds checking — potential buffer overflow.",
        "Use strncpy/strncat with explicit length limits, or safer alternatives "
        "like strlcpy/strlcat where available.",
    ),
    # ── C/C++ sprintf without bounds ────────────────────────────────────────
    (
        "CUSTOM-013",
        Severity.HIGH,
        0,
        r'\bsprintf\s*\(',
        "Use of sprintf without bounds checking — potential buffer overflow.",
        "Replace sprintf with snprintf and always specify the buffer size.",
    ),
    # ── Hardcoded port ───────────────────────────────────────────────────────
    (
        "CUSTOM-014",
        Severity.INFORMATIONAL,
        0,
        r'portNumber\s*=\s*\d+|PORT\s*=\s*\d+',
        "Hardcoded port number detected.",
        "Load port numbers from environment variables or configuration files "
        "to make deployments flexible and avoid accidental exposure.",
    ),
    # ── No authentication on socket ─────────────────────────────────────────
    (
        "CUSTOM-015",
        Severity.MEDIUM,
        re.IGNORECASE,
        r'\baccept\s*\(.*\)',
        "Socket accept() with no visible authentication check.",
        "Implement authentication (e.g., challenge-response, TLS client certs, "
        "or token-based) before processing data from accepted connections.",
    ),
]


class CustomRulesAnalyzer(BaseAnalyzer):
    def analyze(self, code: str, filepath: str, language: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = code.splitlines()

        for rule_id, severity, flags, pattern, description, remediation in CUSTOM_RULES:
            compiled = re.compile(pattern, flags)
            for lineno, line in enumerate(lines, start=1):
                if compiled.search(line):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=lineno,
                            severity=severity,
                            rule_id=rule_id,
                            description=description,
                            remediation=remediation,
                            code_snippet=line.strip(),
                            source_tool="custom",
                        )
                    )
        return findings
