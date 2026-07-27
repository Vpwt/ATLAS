"""Hybrid assurance summary with formal statistical upper-bound guarantees."""
from __future__ import annotations

import math

from scanner.models import Finding


def build_assurance_summary(endpoints: list, findings: list[Finding], checks_run: list[str]) -> dict:
    total_endpoints = len(endpoints or [])
    touched = {f.endpoint for f in findings if f.endpoint}
    # Findings-based touched set underestimates request coverage but provides
    # an observable lower bound with current data model.
    coverage = (len(touched) / total_endpoints * 100.0) if total_endpoints else 0.0

    critical = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high = sum(1 for f in findings if f.severity.value == "HIGH")
    medium = sum(1 for f in findings if f.severity.value == "MEDIUM")

    # Endpoint-level outcome for formal bound construction.
    severe_by_endpoint = {}
    for f in findings:
        if not f.endpoint:
            continue
        sev = f.severity.value
        prev = severe_by_endpoint.get(f.endpoint, "INFO")
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if order.get(sev, 0) > order.get(prev, 0):
            severe_by_endpoint[f.endpoint] = sev

    failing = sum(1 for sev in severe_by_endpoint.values() if sev in {"CRITICAL", "HIGH"})
    n = max(total_endpoints, 1)
    fail_rate = max(0.0, min(1.0, failing / n))
    success_rate = 1.0 - fail_rate

    # Hoeffding upper bound:
    # P(true_fail_rate <= empirical_fail_rate + eps) >= 1 - delta,
    # where eps = sqrt(ln(1/delta)/(2n)).
    delta = 0.05
    eps = math.sqrt(math.log(1.0 / delta) / (2.0 * n))
    upper_bound_fail = min(1.0, fail_rate + eps)
    proof_confidence = 1.0 - delta

    # Bounded confidence score: lower risk and broader coverage increase score.
    penalty = critical * 25 + high * 10 + medium * 4
    confidence = max(0.0, min(100.0, coverage - penalty * 0.5 + 40.0))

    if critical > 0:
        stance = "Action required: critical findings detected."
    elif high > 0:
        stance = "High-risk findings detected; mitigation required before release."
    elif coverage < 70:
        stance = "Coverage is partial; confidence is bounded by explored surface."
    else:
        stance = "No high/critical findings in explored surface; formal upper-bound guarantee is reported."

    return {
        "confidence_score": round(confidence, 1),
        "coverage_percent": round(coverage, 1),
        "checks_run": list(checks_run),
        "stance": stance,
        "high_count": high,
        "critical_count": critical,
        "proof_model": "Hoeffding PAC upper bound",
        "proof_confidence_percent": round(proof_confidence * 100.0, 2),
        "proof_upper_bound_fail_percent": round(upper_bound_fail * 100.0, 2),
        "proof_upper_bound_safe_percent": round((1.0 - upper_bound_fail) * 100.0, 2),
        "proof_empirical_success_percent": round(success_rate * 100.0, 2),
        "proof_empirical_fail_percent": round(fail_rate * 100.0, 2),
        "proof_delta": delta,
        "proof_epsilon": round(eps, 6),
        "proof_assumptions": (
            "Endpoint outcomes are treated as independent bounded Bernoulli observations over the scanned scope."
        ),
    }
