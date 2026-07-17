"""
Base analyzer interface.  Every concrete analyzer must implement `analyze()`.
"""
from abc import ABC, abstractmethod
from app.models.finding import Finding


class BaseAnalyzer(ABC):
    """Accepts source code as a string + the temp file path and returns findings."""

    @abstractmethod
    def analyze(self, code: str, filepath: str, language: str) -> list[Finding]:
        ...
