"""GraphQL-specific checks: introspection exposure and sensitive mutation discovery.

Only runs if `graphql_endpoint` is configured (opt-in, like the `jwt` check
needing a sample token) - most REST-only APIs don't have a GraphQL endpoint
at all, so this avoids sending pointless requests by default.
"""
from scanner.models import Endpoint, Finding, Severity
from scanner.graphql_loader import introspect, summarize_schema

SENSITIVE_MUTATION_HINTS = ("delete", "remove", "admin", "role", "permission",
                            "password", "impersonate", "grant", "promote")


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

    return findings
