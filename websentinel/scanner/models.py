"""
scanner/models.py
==================
Shared data structures used by every check module in WebSentinel.

Keeping this in one small, dependency-free file means every other
module can import a single consistent vocabulary for severities,
findings, and category results.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------
# WebSentinel is deliberately conservative: SEVERITY_* is only used when a
# finding is a directly observable configuration fact (e.g. "this header is
# absent"). Anything that would require exploitation or authenticated
# testing to confirm is represented as `manual_verification=True` instead,
# regardless of severity, and its wording always says "potential" /
# "indicator" / "manual verification required" -- never "confirmed".
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

# Points deducted from a category's 100-point starting sub-score for each
# severity level, when a check fails. INFO never deducts points -- it's
# purely descriptive.
SEVERITY_WEIGHTS = {
    SEVERITY_CRITICAL: 40,
    SEVERITY_HIGH: 25,
    SEVERITY_MEDIUM: 12,
    SEVERITY_LOW: 5,
    SEVERITY_INFO: 0,
}

# Assessment mode
MODE_PASSIVE = "PASSIVE"
MODE_ACTIVE = "AUTHORIZED ACTIVE"


@dataclass
class Finding:
    """A single result from a single check."""

    check_id: str                     # short machine id, e.g. "hsts_present"
    name: str                          # human-friendly name
    passed: bool                       # True = good / present / configured safely
    severity: str = SEVERITY_INFO      # only meaningful when passed is False
    description: str = ""              # what we observed, in plain English
    evidence: str = ""                 # the raw fact behind the finding (header value, etc.)
    recommendation: str = ""           # what to do about it
    manual_verification: bool = False  # True = this cannot be confirmed by passive/safe checks alone

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "passed": self.passed,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "manual_verification": self.manual_verification,
        }


@dataclass
class CategoryResult:
    """All findings for one assessment category, plus its scoring weight."""

    category: str
    weight: int                       # max points this category can contribute (see scanner/scoring.py)
    findings: List[Finding] = field(default_factory=list)
    skipped_reason: Optional[str] = None  # set if this category could not run at all

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def sub_score(self) -> int:
        """0-100 internal quality score for this category, before weighting."""
        if self.skipped_reason:
            return 0
        score = 100
        for f in self.findings:
            if not f.passed:
                score -= SEVERITY_WEIGHTS.get(f.severity, 0)
        return max(0, score)

    def weighted_score(self) -> float:
        """This category's contribution to the overall 100-point score."""
        return round((self.sub_score() / 100) * self.weight, 2)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "weight": self.weight,
            "sub_score": self.sub_score(),
            "weighted_score": self.weighted_score(),
            "skipped_reason": self.skipped_reason,
            "findings": [f.to_dict() for f in self.findings],
        }
