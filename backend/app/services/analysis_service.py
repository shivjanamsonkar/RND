"""
Analysis service — orchestrates all analyzers, deduplicates findings,
and returns a completed Report.
"""
from app.analyzers.bandit_analyzer import BanditAnalyzer
from app.analyzers.semgrep_analyzer import SemgrepAnalyzer
from app.analyzers.custom_rules import CustomRulesAnalyzer
from app.models.finding import Finding
from app.models.report import Report

_ANALYZERS = [
    CustomRulesAnalyzer(),   # always runs (fast, no subprocess)
    BanditAnalyzer(),         # Python-only
    SemgrepAnalyzer(),        # any language
]

SUPPORTED_LANGUAGES = {
    "python", "javascript", "typescript", "java", "c", "cpp", "go", "ruby", "php"
}

EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove exact duplicates (same file, line, rule_id)."""
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze_code(code: str, filename: str, language: str | None = None) -> Report:
    """
    Run all applicable analyzers on `code` and return a Report.

    If `language` is None, it is inferred from the file extension.
    """
    if not language:
        import os
        ext = os.path.splitext(filename)[1].lower()
        language = EXTENSION_TO_LANGUAGE.get(ext, "unknown")

    language = language.lower()

    all_findings: list[Finding] = []
    for analyzer in _ANALYZERS:
        try:
            results = analyzer.analyze(code, filename, language)
            all_findings.extend(results)
        except Exception:
            # Never let a single analyzer failure crash the whole scan
            pass

    findings = _deduplicate(all_findings)
    # Sort: highest severity first, then by line number
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.line or 0))

    return Report.from_findings(findings, filename=filename, language=language)
