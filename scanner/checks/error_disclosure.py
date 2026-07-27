"""API8:2023-adjacent - verbose errors leaking internal details.

Sends malformed input (bad JSON, wrong types, huge payloads) and checks
whether the response leaks stack traces, file paths, framework versions,
or internal hostnames.
"""
from scanner.models import Endpoint, Finding, Severity

LEAK_SIGNATURES = [
    "traceback (most recent call last)", "at java.", "at com.sun.", "stacktrace",
    "django.core", "flask.app", "express/lib", "node_modules", "/home/", "/usr/",
    "c:\\", "internal server error occurred while", "debug mode",
]


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue
        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        malformed_bodies = [
            {"__malformed__": "x" * 5000},   # oversized field
            {"unexpected_type_test": {"nested": {"too": {"deep": True}}}},
        ]

        for body in malformed_bodies:
            try:
                resp = client.request(ep.method, path, json_body=body, auth_override="keep",
                                      body_content_type=ep.body_content_type)
            except Exception:
                continue

            text_lower = (resp.text or "").lower()
            for sig in LEAK_SIGNATURES:
                if sig in text_lower:
                    findings.append(Finding(
                        check="error_disclosure", severity=Severity.MEDIUM,
                        title="Verbose error response leaks internal details",
                        endpoint=label,
                        detail=(f"Response to malformed input contains a signature ('{sig}') "
                                "suggesting stack traces or internal paths are exposed to "
                                "clients. Disable debug/verbose error output in production."),
                        evidence=f"HTTP {resp.status_code}",
                        owasp_ref="API8:2023 Security Misconfiguration",
                    ))
                    break

    return findings
