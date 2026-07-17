"""
Unified finding model — every analyzer normalizes its raw output to this schema.
"""
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


SEVERITY_SCORE: dict[str, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}


class Finding(BaseModel):
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    severity: Severity
    rule_id: str
    description: str
    remediation: str
    code_snippet: Optional[str] = None
    source_tool: str  # e.g. "bandit", "semgrep", "custom"
