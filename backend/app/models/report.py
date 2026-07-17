"""
Report model – wraps findings with metadata for storage and display.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
import uuid

from app.models.finding import Finding, Severity, SEVERITY_SCORE


class Report(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    language: str
    filename: str
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    security_score: int = 100  # starts at 100, deducted per finding
    findings: list[Finding] = []

    @classmethod
    def from_findings(cls, findings: list[Finding], filename: str, language: str) -> "Report":
        counts: dict[str, int] = {s: 0 for s in Severity}
        total_deduction = 0
        for f in findings:
            counts[f.severity] += 1
            total_deduction += SEVERITY_SCORE[f.severity]

        score = max(0, 100 - total_deduction)

        return cls(
            language=language,
            filename=filename,
            total_findings=len(findings),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            informational=counts[Severity.INFORMATIONAL],
            security_score=score,
            findings=findings,
        )
