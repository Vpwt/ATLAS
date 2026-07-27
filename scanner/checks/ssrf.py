"""API7:2023 - Server Side Request Forgery (SSRF).

Looks for parameters/body fields whose names suggest the API fetches a
URL/resource on the caller's behalf (webhooks, callback URLs, image/avatar
fetchers, redirect targets, etc.) and probes them with URLs pointing at
cloud metadata services, loopback addresses, and local files. Flags a
finding when the response contains strong evidence the server actually
followed the request (leaked cloud credentials, file contents, etc.), and a
lower-confidence INFO finding on suspiciously slow responses.
"""
import time
from scanner.models import Endpoint, Finding, Severity

SSRF_PRONE_NAMES = (
    "url", "uri", "link", "callback", "webhook", "redirect", "return_url",
    "next", "target", "endpoint", "src", "source", "image", "avatar",
    "feed", "site", "host", "domain", "file", "fetch",
)

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "http://localhost:6379",
    "file:///etc/passwd",
]

LEAK_SIGNATURES = [
    "accesskeyid", "secretaccesskey", "root:x:0:0", "ssh-2.0", "instance-id",
]


def _looks_ssrf_prone(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in SSRF_PRONE_NAMES)


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        candidate_fields = {n for n in ep.params if _looks_ssrf_prone(n)}
        candidate_fields |= {n for n in (ep.body or {}) if _looks_ssrf_prone(n)}
        if not candidate_fields:
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        for field in candidate_fields:
            for payload in SSRF_PAYLOADS:
                test_params = dict(ep.params)
                test_body = dict(ep.body) if ep.body else None
                if field in test_params:
                    test_params[field] = payload
                if test_body is not None and field in test_body:
                    test_body[field] = payload

                start = time.monotonic()
                try:
                    resp = client.request(ep.method, path,
                                           params=test_params if ep.method == "GET" else None,
                                           json_body=test_body if ep.method in ("POST", "PUT", "PATCH") else None,
                                           auth_override="keep")
                except Exception:
                    continue
                elapsed = time.monotonic() - start

                body_lower = (resp.text or "").lower()
                leaked = [sig for sig in LEAK_SIGNATURES if sig in body_lower]
                if leaked:
                    findings.append(Finding(
                        check="ssrf", severity=Severity.CRITICAL,
                        title="Possible SSRF: server appears to have fetched an internal resource",
                        endpoint=label,
                        detail=(f"Sending an internal/metadata URL into parameter '{field}' "
                                "produced a response containing signature(s) consistent with "
                                f"cloud metadata or local file contents: {leaked}. This strongly "
                                "suggests the server is making outbound requests based on "
                                "unvalidated user input."),
                        evidence=f"payload={payload!r}",
                        owasp_ref="API7:2023 Server Side Request Forgery",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))
                elif elapsed > client.timeout * 0.8:
                    findings.append(Finding(
                        check="ssrf", severity=Severity.INFO,
                        title="Slow response after sending internal-looking URL - review for SSRF",
                        endpoint=label,
                        detail=(f"Parameter '{field}' looks like it may accept a URL, and the "
                                f"request took {elapsed:.1f}s (close to the {client.timeout}s "
                                "timeout) after sending an internal address. This can indicate "
                                "the server attempted to connect to an unreachable internal "
                                "host. Manual review recommended."),
                        evidence=f"payload={payload!r}, elapsed={elapsed:.1f}s",
                        owasp_ref="API7:2023 Server Side Request Forgery",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))

    return findings
