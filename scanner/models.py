"""Core data models used across the scanner."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Rough ordering so reports can be sorted by severity
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def severity_rank(sev: Severity) -> int:
    return _SEVERITY_ORDER.get(sev, 99)


# Rough severity -> CVSS v3.1 base score mapping. This is an approximation
# (a single representative score per bucket) rather than a full CVSS vector
# calculation, but it's enough to give findings a familiar risk number for
# reporting/triage purposes.
_SEVERITY_CVSS = {
    Severity.CRITICAL: 9.8,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.3,
    Severity.LOW: 3.1,
    Severity.INFO: 0.0,
}


def severity_to_cvss(sev: Severity) -> float:
    return _SEVERITY_CVSS.get(sev, 0.0)


@dataclass
class Endpoint:
    """A single API endpoint to test, as declared in the config file."""
    path: str                          # e.g. "/api/users/{id}"
    method: str = "GET"                # GET, POST, PUT, DELETE, PATCH
    auth_required: bool = True         # should this endpoint require auth?
    params: dict = field(default_factory=dict)   # query params, {id} placeholders resolved here
    body: Optional[dict] = None        # JSON body template for POST/PUT/PATCH
    id_param: Optional[str] = None     # name of the path/query param that is an object ID (for BOLA tests)
    sample_ids: list = field(default_factory=list)  # ids the authenticated user IS allowed to access
    foreign_ids: list = field(default_factory=list)  # ids belonging to OTHER users/objects (for BOLA tests)
    admin_only: bool = False           # should only be reachable by an admin/privileged identity (for BFLA tests)
    description: str = ""

    def resolved_path(self, overrides: Optional[dict] = None) -> str:
        """Return path with {placeholders} substituted using params (and overrides)."""
        values = dict(self.params)
        if overrides:
            values.update(overrides)
        path = self.path
        for key, val in values.items():
            path = path.replace("{" + key + "}", str(val))
        return path


@dataclass
class Finding:
    """A single security finding produced by a check module."""
    check: str              # which check module produced this
    severity: Severity
    title: str
    endpoint: str            # method + path, for display
    detail: str              # human-readable explanation
    evidence: str = ""       # short snippet of evidence (status code, header, response fragment)
    owasp_ref: str = ""      # e.g. "API1:2023 Broken Object Level Authorization"
    curl_repro: str = ""    # optional curl command to reproduce the request that triggered this

    @property
    def cvss_score(self) -> float:
        return severity_to_cvss(self.severity)
