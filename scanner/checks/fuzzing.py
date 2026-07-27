"""API fuzzing check using mutation-based payload generation."""
from __future__ import annotations

from scanner.models import Endpoint, Finding, Severity
from scanner.mutation_engine import generate_mutations


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue
        if not isinstance(ep.body, dict) or not ep.body:
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"
        mutations = generate_mutations(ep.body)
        if not mutations:
            continue

        for idx, mutated in enumerate(mutations[:6], start=1):
            try:
                resp = client.request(
                    ep.method,
                    path,
                    json_body=mutated,
                    auth_override="keep",
                    body_content_type=ep.body_content_type,
                )
            except Exception:
                continue

            if resp.status_code >= 500:
                findings.append(Finding(
                    check="fuzzing",
                    severity=Severity.HIGH,
                    title="Mutation fuzzing triggered server error",
                    endpoint=label,
                    detail="A structured mutation caused a 5xx response. Investigate parser robustness and input handling.",
                    evidence=f"mutation=#{idx}, status={resp.status_code}",
                    owasp_ref="API8:2023 Security Misconfiguration",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
                break
            if resp.status_code < 300 and idx == 1:
                findings.append(Finding(
                    check="fuzzing",
                    severity=Severity.INFO,
                    title="Fuzz baseline accepted",
                    endpoint=label,
                    detail="Endpoint accepted at least one mutation payload. Review server-side validation depth.",
                    evidence=f"mutation=#{idx}, status={resp.status_code}",
                    owasp_ref="API8:2023 Security Misconfiguration",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))

    return findings
