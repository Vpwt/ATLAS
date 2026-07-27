"""API4:2023 - Unrestricted Resource Consumption (missing rate limiting)."""
from scanner.models import Endpoint, Finding, Severity

BURST_COUNT = 25  # keep modest by default to avoid hammering a real API too hard
PAGINATION_PARAM_NAMES = ("limit", "per_page", "page_size", "count", "size", "top")
LARGE_PAGE_VALUE = 100000


def run(client, endpoints: list[Endpoint], burst_count: int = BURST_COUNT) -> list[Finding]:
    findings = []

    for ep in endpoints:
        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        statuses = []
        for _ in range(burst_count):
            try:
                resp = client.request(ep.method, path, params=ep.params if ep.method == "GET" else None,
                                       json_body=ep.body, auth_override="keep")
                statuses.append(resp.status_code)
            except Exception:
                statuses.append(None)

        throttled = any(s == 429 for s in statuses)
        successes = sum(1 for s in statuses if s is not None and s < 400)

        if not throttled and successes == burst_count:
            findings.append(Finding(
                check="rate_limit", severity=Severity.MEDIUM,
                title="No rate limiting detected",
                endpoint=label,
                detail=(f"Sent {burst_count} requests in quick succession and all succeeded with "
                        "no HTTP 429 (Too Many Requests) response. Consider adding rate limiting "
                        "to protect against abuse, brute force, and resource exhaustion."),
                evidence=f"{successes}/{burst_count} requests succeeded, no 429 seen",
                owasp_ref="API4:2023 Unrestricted Resource Consumption",
            ))

        findings.extend(_check_pagination_abuse(client, ep, label))

    return findings


def _check_pagination_abuse(client, ep: Endpoint, label: str) -> list:
    """Requests a very large page size/limit and flags an uncapped response."""
    candidate = next((p for p in ep.params if p.lower() in PAGINATION_PARAM_NAMES), None)
    if not candidate:
        return []

    path = ep.resolved_path()
    test_params = dict(ep.params)
    test_params[candidate] = LARGE_PAGE_VALUE

    try:
        resp = client.request(ep.method, path, params=test_params if ep.method == "GET" else None,
                               json_body=ep.body, auth_override="keep")
    except Exception:
        return []

    if resp.status_code >= 300:
        return []

    try:
        data = resp.json()
    except ValueError:
        return []

    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next((v for v in data.values() if isinstance(v, list)), None)

    if isinstance(items, list) and len(items) > 500:
        return [Finding(
            check="rate_limit", severity=Severity.MEDIUM,
            title="No cap on pagination/page-size parameter",
            endpoint=label,
            detail=(f"Requesting '{candidate}={LARGE_PAGE_VALUE}' returned {len(items)} items in "
                    "a single response with no apparent server-side cap. Uncapped page sizes can "
                    "be used for resource-exhaustion or bulk-scraping attacks."),
            evidence=f"{len(items)} items returned",
            owasp_ref="API4:2023 Unrestricted Resource Consumption",
        )]

    return []
