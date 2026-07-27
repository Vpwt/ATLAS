"""Example plugin check.

This file demonstrates the expected plugin entrypoint signature.
"""
from scanner.models import Finding, Severity


def run(client, endpoints, **kwargs):
    findings = []
    oauth_paths = [ep for ep in endpoints if "oauth" in ep.path.lower() or "token" in ep.path.lower()]
    if oauth_paths:
        findings.append(Finding(
            check="example_oauth_scanner",
            severity=Severity.INFO,
            title="OAuth-related endpoints detected",
            endpoint=f"{oauth_paths[0].method} {oauth_paths[0].path}",
            detail="External plugin successfully executed and found OAuth-like paths.",
            evidence=f"count={len(oauth_paths)}",
        ))
    return findings
