"""Deterministic remediation and exploit-guidance assistant for findings."""
from __future__ import annotations

from scanner.models import Finding


_GUIDANCE = {
    "auth": {
        "cwe": "CWE-306",
        "remediation": "Enforce authn/authz middleware on every protected route and reject invalid/absent tokens with 401/403.",
        "exploit_hint": "Try replaying with missing token, expired token, and malformed JWT to validate hard-fail behavior.",
    },
    "bola": {
        "cwe": "CWE-639",
        "remediation": "Perform per-object ownership checks server-side before returning or mutating records.",
        "exploit_hint": "Test neighboring IDs, UUID variants, and cross-tenant identifiers for unauthorized access.",
    },
    "bfla": {
        "cwe": "CWE-285",
        "remediation": "Apply role/permission authorization per action, not per UI route or endpoint prefix.",
        "exploit_hint": "Try non-admin tokens on admin-only verbs and alternate HTTP methods.",
    },
    "mass_assignment": {
        "cwe": "CWE-915",
        "remediation": "Use explicit allow-lists/DTOs for writable fields and ignore privileged attributes from client input.",
        "exploit_hint": "Try role=admin, permissions=*, is_superuser=true, account_status=active.",
    },
    "ssrf": {
        "cwe": "CWE-918",
        "remediation": "Enforce strict URL allow-lists, block link-local/private ranges, and validate schemes.",
        "exploit_hint": "Probe metadata endpoints, localhost variants, DNS rebinding targets, and file schemes.",
    },
    "rate_limit": {
        "cwe": "CWE-770",
        "remediation": "Apply per-user and per-IP rate limits with hard ceilings on expensive operations.",
        "exploit_hint": "Burst requests with changing IP/user-agent and inspect 429 behavior and retry headers.",
    },
    "injection": {
        "cwe": "CWE-89",
        "remediation": "Use parameterized queries and strict input validation/encoding for every backend interpreter.",
        "exploit_hint": "Follow-up with boolean/time-based payload permutations and context-specific encodings.",
    },
}


def enrich_findings_with_assistance(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        guide = _GUIDANCE.get(finding.check)
        if not guide:
            continue
        if not finding.cwe:
            finding.cwe = guide["cwe"]
        if not finding.remediation:
            finding.remediation = guide["remediation"]
        if not finding.exploit_hint:
            finding.exploit_hint = guide["exploit_hint"]
    return findings
