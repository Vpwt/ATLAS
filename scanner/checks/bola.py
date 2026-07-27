"""API1:2023 - Broken Object Level Authorization (BOLA / IDOR).

For endpoints that declare an id_param plus sample_ids (objects the
authenticated user legitimately owns) and foreign_ids (objects belonging
to someone else), this check verifies that swapping in a foreign id is
rejected rather than served.
"""
from scanner.models import Endpoint, Finding, Severity


def _heuristic_foreign_ids(ep: Endpoint) -> list:
    """Best-effort foreign ID generation to reduce manual config burden.

    This is intentionally conservative and marks findings as lower confidence
    elsewhere if only heuristic IDs are available.
    """
    candidates = []

    # Prefer deriving from explicitly provided sample IDs.
    for sid in ep.sample_ids or []:
        if isinstance(sid, int):
            candidates.extend([sid + 1, sid + 2])
        elif isinstance(sid, str) and sid.isdigit():
            n = int(sid)
            candidates.extend([str(n + 1), str(n + 2)])

    # Fall back to the configured ID parameter itself.
    raw = ep.params.get(ep.id_param) if ep.id_param else None
    if isinstance(raw, int):
        candidates.extend([raw + 1, raw + 2])
    elif isinstance(raw, str) and raw.isdigit():
        n = int(raw)
        candidates.extend([str(n + 1), str(n + 2)])

    unique = []
    seen = set()
    for val in candidates:
        if val not in seen:
            seen.add(val)
            unique.append(val)
    return unique[:3]


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if not ep.id_param:
            continue  # nothing to test BOLA against

        foreign_ids = list(ep.foreign_ids or [])
        heuristic_only = False
        if not foreign_ids:
            foreign_ids = _heuristic_foreign_ids(ep)
            heuristic_only = bool(foreign_ids)
        if not foreign_ids:
            continue

        for foreign_id in foreign_ids:
            overrides = {ep.id_param: foreign_id}
            path = ep.resolved_path(overrides)
            params = dict(ep.params)
            if ep.id_param in params:
                params[ep.id_param] = foreign_id
            label = f"{ep.method} {path}"

            try:
                resp = client.request(ep.method, path, params=params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep",
                                       body_content_type=ep.body_content_type)
            except Exception:
                continue

            if resp.status_code < 300:
                findings.append(Finding(
                    check="bola", severity=Severity.HIGH if heuristic_only else Severity.CRITICAL,
                    title=("Possible BOLA / IDOR: heuristic foreign object ID returned data"
                           if heuristic_only else "Possible BOLA / IDOR: foreign object ID returned data"),
                    endpoint=label,
                    detail=(f"Requesting {ep.id_param}={foreign_id} (an object not owned by the "
                            "authenticated test account) returned a success response instead of "
                            "403/404. Verify object-level authorization checks server-side." +
                            (" This used an auto-generated candidate ID because foreign_ids were "
                             "not configured explicitly." if heuristic_only else "")),
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
