"""Lightweight injection probes (SQL / NoSQL / command-ish payloads).

This is NOT a substitute for a dedicated tool like sqlmap - it's a fast,
low-noise smoke test that looks for obvious signs of unsanitized input:
server errors, stack traces, or reflected payloads in responses.
"""
from scanner.models import Endpoint, Finding, Severity

# Deliberately simple, low-impact payloads meant to trigger errors/anomalies,
# not to actually exfiltrate or damage data. Covers SQL/NoSQL/command/SSTI/LDAP
# injection, a couple of deserialization gadget markers, plus a basic
# reflected-XSS smoke test.
PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    '{"$ne": null}',
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "; cat /etc/passwd",
    "| whoami",
    "$(whoami)",
    "{{7*7}}",
    "*)(uid=*))(|(uid=*",
    'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',  # PHP object injection marker
    "rO0ABXQABHRlc3Q=",                             # Java serialized-object (base64) marker
]

ERROR_SIGNATURES = [
    "sql syntax", "sqlstate", "ora-", "postgresql", "sqlite3.operationalerror",
    "unclosed quotation mark", "traceback (most recent call last)",
    "system.data.sqlclient", "you have an error in your sql syntax",
    "root:x:0:0", "command not found", "/bin/sh:", "uid=0(root)",
    "no such file or directory", "unserialize()", "objectinputstream",
    "java.io.invalidclassexception", "picklingerror", "__reduce__",
]


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if not ep.params:
            continue  # nothing to inject into

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        for param_name in ep.params:
            for payload in PAYLOADS:
                test_params = dict(ep.params)
                test_params[param_name] = payload

                try:
                    resp = client.request(ep.method, path,
                                           params=test_params if ep.method == "GET" else None,
                                           json_body={**(ep.body or {}), param_name: payload}
                                           if ep.method in ("POST", "PUT", "PATCH") else None,
                                           auth_override="keep")
                except Exception:
                    continue

                body_lower = (resp.text or "").lower()

                if resp.status_code >= 500:
                    findings.append(Finding(
                        check="injection", severity=Severity.HIGH,
                        title="Server error triggered by injection-style payload",
                        endpoint=label,
                        detail=(f"Sending payload into parameter '{param_name}' caused a 5xx "
                                "response. This can indicate unsanitized input reaching a "
                                "backend query or interpreter."),
                        evidence=f"HTTP {resp.status_code}, payload={payload!r}",
                        owasp_ref="API8:2023 Security Misconfiguration / Injection",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))
                    continue

                for sig in ERROR_SIGNATURES:
                    if sig in body_lower:
                        findings.append(Finding(
                            check="injection", severity=Severity.CRITICAL,
                            title="Database/stack error signature leaked in response",
                            endpoint=label,
                            detail=(f"Response body contains a signature ('{sig}') consistent "
                                    "with a leaked database error or stack trace after sending "
                                    f"an injection-style payload into '{param_name}'."),
                            evidence=f"payload={payload!r}",
                            owasp_ref="API8:2023 Security Misconfiguration / Injection",
                            curl_repro=getattr(resp, "curl_repro", ""),
                        ))
                        break

                # Basic reflected-XSS smoke test: does the raw HTML payload come
                # back unescaped in the response body?
                if payload.strip().startswith("<") and payload in (resp.text or ""):
                    findings.append(Finding(
                        check="injection", severity=Severity.HIGH,
                        title="Payload reflected unescaped in response (possible XSS)",
                        endpoint=label,
                        detail=(f"The payload sent in '{param_name}' was reflected back verbatim "
                                "and unescaped in the response body. If this response is ever "
                                "rendered as HTML by a client, this can lead to reflected XSS."),
                        evidence=f"payload={payload!r}",
                        owasp_ref="API8:2023 Security Misconfiguration / Injection",
                        curl_repro=getattr(resp, "curl_repro", ""),
                    ))

    return findings
