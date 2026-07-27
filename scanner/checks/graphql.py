"""GraphQL-specific checks: introspection exposure, sensitive mutation
discovery, query depth/complexity DoS, and alias-based batching abuse.

Only runs if `graphql_endpoint` is configured (opt-in, like the `jwt` check
needing a sample token) - most REST-only APIs don't have a GraphQL endpoint
at all, so this avoids sending pointless requests by default.
"""
import json
import time
from scanner.models import Endpoint, Finding, Severity
from scanner.graphql_loader import (
    introspect, summarize_schema, find_deep_query, build_alias_batch_query,
)

SENSITIVE_MUTATION_HINTS = ("delete", "remove", "admin", "role", "permission",
                            "password", "impersonate", "grant", "promote")

# Response error text containing any of these suggests the server actually
# has some protection in place (depth/complexity limiting, batching limits).
DEPTH_PROTECTION_HINTS = ("depth", "complexity", "too deep", "max depth", "cost", "nesting")
BATCH_PROTECTION_HINTS = ("alias", "too many", "complexity", "rate limit", "batch", "throttle")


def run(client, endpoints: list[Endpoint], graphql_path: str = None) -> list[Finding]:
    findings = []
    if not graphql_path:
        return findings

    result = introspect(client, graphql_path)
    summary = summarize_schema(result)
    if not summary:
        return findings  # no GraphQL endpoint found, or introspection disabled - good sign either way

    findings.append(Finding(
        check="graphql", severity=Severity.MEDIUM,
        title="GraphQL introspection is enabled",
        endpoint=f"POST {graphql_path}",
        detail=(f"The GraphQL endpoint responded to a standard introspection query, exposing "
                f"the full schema ({summary['type_count']} types, {len(summary['queries'])} "
                f"queries, {len(summary['mutations'])} mutations). Introspection should "
                "typically be disabled in production - it hands an attacker a complete map of "
                "your API's query/mutation surface."),
        evidence=f"queries={summary['queries'][:10]}",
        owasp_ref="API9:2023 Improper Inventory Management",
    ))

    sensitive = [m for m in summary["mutations"] if any(h in m.lower() for h in SENSITIVE_MUTATION_HINTS)]
    if sensitive:
        findings.append(Finding(
            check="graphql", severity=Severity.HIGH,
            title="Sensitive-sounding GraphQL mutations discovered via introspection",
            endpoint=f"POST {graphql_path}",
            detail=(f"Introspection revealed mutation(s) that sound privileged or destructive: "
                    f"{sensitive}. Manually verify these enforce proper object/function-level "
                    "authorization and aren't reachable by low-privilege or unauthenticated "
                    "callers."),
            evidence=f"mutations={sensitive}",
            owasp_ref="API5:2023 Broken Function Level Authorization",
        ))

    schema = (result or {}).get("data", {}).get("__schema") if result else None
    query_type_name = (schema.get("queryType") or {}).get("name") if schema else None

    if schema and query_type_name:
        findings.extend(_check_query_depth(client, graphql_path, schema, query_type_name))
        findings.extend(_check_alias_batching(client, graphql_path, schema, query_type_name))

    return findings


def _response_errors_text(resp) -> str:
    try:
        body = resp.json()
    except ValueError:
        return ""
    errors = body.get("errors") if isinstance(body, dict) else None
    return json.dumps(errors).lower() if errors else ""


def _check_query_depth(client, graphql_path: str, schema: dict, query_type_name: str) -> list[Finding]:
    """API4:2023 Unrestricted Resource Consumption: sends a deeply-nested
    query and flags it if the server accepts it without any sign of a
    depth/complexity limit - a common vector for resource-exhaustion DoS."""
    deep_query = find_deep_query(schema, query_type_name, max_depth=15)
    if not deep_query:
        return []

    start = time.monotonic()
    try:
        resp = client.request("POST", graphql_path, json_body={"query": deep_query}, auth_override="keep")
    except Exception:
        return []
    elapsed = time.monotonic() - start

    error_text = _response_errors_text(resp)
    if resp.status_code < 300 and not any(h in error_text for h in DEPTH_PROTECTION_HINTS):
        return [Finding(
            check="graphql", severity=Severity.HIGH,
            title="No GraphQL query depth/complexity limit detected (possible DoS)",
            endpoint=f"POST {graphql_path}",
            detail=("A deeply-nested query (built recursively from the discovered schema) was "
                    "accepted without any depth/complexity-limit error. Without such a limit, "
                    "an attacker can craft an arbitrarily deep or expensive query to exhaust "
                    "server resources (CPU, DB connections) with a single request. Consider "
                    "adding query depth/cost limiting (e.g. graphql-depth-limit, "
                    "graphql-cost-analysis, or persisted queries)."),
            evidence=f"HTTP {resp.status_code}, elapsed={elapsed:.1f}s, attempted nesting depth up to 15",
            owasp_ref="API4:2023 Unrestricted Resource Consumption",
            curl_repro=getattr(resp, "curl_repro", ""),
        )]
    return []


def _check_alias_batching(client, graphql_path: str, schema: dict, query_type_name: str) -> list[Finding]:
    """API4:2023 Unrestricted Resource Consumption: sends one request
    containing many aliases of the same root field, and flags it if accepted
    without limit - a well-known way to bypass per-request rate limiting
    (N units of work counted as a single HTTP request/operation)."""
    batch_query = build_alias_batch_query(schema, query_type_name, batch_size=50)
    if not batch_query:
        return []

    try:
        resp = client.request("POST", graphql_path, json_body={"query": batch_query}, auth_override="keep")
    except Exception:
        return []

    error_text = _response_errors_text(resp)
    if resp.status_code < 300 and not any(h in error_text for h in BATCH_PROTECTION_HINTS):
        return [Finding(
            check="graphql", severity=Severity.MEDIUM,
            title="No GraphQL alias/batching limit detected (possible rate-limit bypass)",
            endpoint=f"POST {graphql_path}",
            detail=("A single request containing 50 aliased copies of the same root field was "
                    "accepted without error. Per-request rate limiting is easily bypassed this "
                    "way, since many logical operations are smuggled inside one HTTP request. "
                    "Consider counting aliases/operation complexity toward rate limits, not just "
                    "request count."),
            evidence=f"HTTP {resp.status_code}, 50 aliased sub-queries in one request",
            owasp_ref="API4:2023 Unrestricted Resource Consumption",
            curl_repro=getattr(resp, "curl_repro", ""),
        )]
    return []
