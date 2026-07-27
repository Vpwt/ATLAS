"""API1:2023 - Broken Object Level Authorization (BOLA / IDOR).

For endpoints that declare an id_param plus sample_ids (objects the
authenticated user legitimately owns) and foreign_ids (objects belonging
to someone else), this check verifies that swapping in a foreign id is
rejected rather than served.
"""
from scanner.models import Endpoint, Finding, Severity


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if not ep.id_param or not ep.foreign_ids:
            continue  # nothing to test BOLA against

        for foreign_id in ep.foreign_ids:
            overrides = {ep.id_param: foreign_id}
            path = ep.resolved_path(overrides)
            params = dict(ep.params)
            if ep.id_param in params:
                params[ep.id_param] = foreign_id
            label = f"{ep.method} {path}"

            try:
                resp = client.request(ep.method, path, params=params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep")
            except Exception:
                continue

            if resp.status_code < 300:
                findings.append(Finding(
                    check="bola", severity=Severity.CRITICAL,
                    title="Possible BOLA / IDOR: foreign object ID returned data",
                    endpoint=label,
                    detail=(f"Requesting {ep.id_param}={foreign_id} (an object not owned by the "
                            "authenticated test account) returned a success response instead of "
                            "403/404. Verify object-level authorization checks server-side."),
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API1:2023 Broken Object Level Authorization",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
            elif resp.status_code not in (401, 403, 404):
                findings.append(Finding(
                    check="bola", severity=Severity.LOW,
                    title="Unexpected status code on foreign object ID test",
                    endpoint=label,
                    detail="Expected 401/403/404 for a foreign object ID; got a different status.",
                    evidence=f"HTTP {resp.status_code}",
                    owasp_ref="API1:2023 Broken Object Level Authorization",
                ))

    return findings
