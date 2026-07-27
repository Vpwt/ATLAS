"""API10:2023 - Unsafe Consumption of APIs (heuristic, black-box).

Black-box scanners cannot see internal upstream integrations directly.
This module uses heuristics to surface suspicious patterns where user input
appears to control outbound fetch behavior without adequate validation.

It focuses on URL-like parameters and checks whether risky schemes/hosts are
accepted and processed, which can indicate unsafe downstream API consumption
or weak egress validation.
"""
from scanner.models import Endpoint, Finding, Severity

URL_LIKE_NAMES = (
    "url", "uri", "endpoint", "callback", "webhook", "target", "redirect",
    "next", "source", "src", "feed", "proxy", "upstream",
)

RISKY_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://169.254.169.254/latest/meta-data/",
    "ftp://example.com/resource.txt",
    "file:///etc/passwd",
]

UPSTREAM_LEAK_HINTS = (
    "upstream", "gateway", "proxy", "connection refused", "timed out",
    "no such host", "dial tcp", "dns", "fetch failed", "unable to resolve",
)


def _is_url_like(name: str) -> bool:
    lower = name.lower()
    return any(h in lower for h in URL_LIKE_NAMES)


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        fields = {n for n in ep.params if _is_url_like(n)}
        fields |= {n for n in (ep.body or {}) if _is_url_like(n)}
        if not fields:
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        for field in fields:
            for payload in RISKY_PAYLOADS:
                test_params = dict(ep.params)
                test_body = dict(ep.body) if ep.body else None
                if field in test_params:
                    test_params[field] = payload
                if test_body is not None and field in test_body:
                    test_body[field] = payload

                try:
                    resp = client.request(
                        ep.method,
                        path,
                        params=test_params if ep.method == "GET" else None,
                        json_body=test_body if ep.method in ("POST", "PUT", "PATCH") else None,
                        auth_override="keep",
                        body_content_type=ep.body_content_type,
                    )
                except Exception:
                    continue

                text = (resp.text or "").lower()
                if resp.status_code < 300:
                    findings.append(Finding(
                        check="unsafe_consumption",
                        severity=Severity.MEDIUM,
                        title="Potential unsafe upstream API consumption",
                        endpoint=label,
                        detail=(
                            f"URL-like field '{field}' accepted risky upstream target '{payload}' "
                            "with a success response. Review outbound allow-listing, scheme "
                            "validation, DNS/IP pinning, and egress controls for integrations "
                            "that consume external/internal APIs."
                        ),
                        evidence=f"HTTP {resp.status_code}, payload={payload!r}",
                        owasp_ref="API10:2023 Unsafe Consumption of APIs",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))
                elif any(h in text for h in UPSTREAM_LEAK_HINTS):
                    findings.append(Finding(
                        check="unsafe_consumption",
                        severity=Severity.LOW,
                        title="Upstream integration error details leaked",
                        endpoint=label,
                        detail=(
                            f"Response for URL-like field '{field}' included upstream/network "
                            "error details after a risky target input. This can leak integration "
                            "internals and often correlates with weak outbound validation."
                        ),
                        evidence=f"HTTP {resp.status_code}, payload={payload!r}",
                        owasp_ref="API10:2023 Unsafe Consumption of APIs",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))

    return findings
