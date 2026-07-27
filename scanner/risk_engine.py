"""Risk scoring and attack-chain correlation."""
from __future__ import annotations

from scanner.models import Finding


SEVERITY_POINTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 0,
}


def build_risk_summary(findings: list[Finding]) -> dict:
    by_check = {}
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    points = 0
    for f in findings:
        sev = f.severity.value
        counts[sev] = counts.get(sev, 0) + 1
        by_check[f.check] = by_check.get(f.check, 0) + 1
        points += SEVERITY_POINTS.get(sev, 0)

    score = min(100, points)
    chains = _attack_chains(findings)
    if chains:
        score = min(100, score + 10)

    return {
        "risk_score": score,
        "counts": counts,
        "by_check": by_check,
        "attack_chains": chains,
    }


def _has(findings: list[Finding], check: str, sev_min: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")) -> bool:
    return any(f.check == check and f.severity.value in sev_min for f in findings)


def _attack_chains(findings: list[Finding]) -> list[dict]:
    chains = []

    if _has(findings, "jwt", ("HIGH", "CRITICAL")) and _has(findings, "mass_assignment") and _has(findings, "bfla"):
        chains.append({
            "name": "Privilege escalation chain",
            "severity": "CRITICAL",
            "steps": ["JWT weakness", "Mass assignment", "Admin/API function-level bypass"],
            "impact": "Attacker can forge/escalate identity and reach privileged operations.",
        })

    if _has(findings, "auth", ("HIGH", "CRITICAL")) and _has(findings, "bola") and _has(findings, "excessive_data_exposure"):
        chains.append({
            "name": "Account takeover and data exfiltration chain",
            "severity": "HIGH",
            "steps": ["Broken auth", "BOLA/IDOR", "Excessive data exposure"],
            "impact": "Attacker can enumerate objects and extract sensitive records at scale.",
        })

    if _has(findings, "ssrf") and _has(findings, "unsafe_consumption"):
        chains.append({
            "name": "Upstream pivot chain",
            "severity": "HIGH",
            "steps": ["SSRF", "Unsafe upstream consumption"],
            "impact": "Attacker can pivot into internal services and metadata endpoints.",
        })

    return chains
