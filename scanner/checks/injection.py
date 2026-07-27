"""Lightweight injection probes (SQL / NoSQL / command-ish payloads).

This is NOT a substitute for a dedicated tool like sqlmap - it's a fast,
low-noise smoke test that looks for obvious signs of unsanitized input:
server errors, stack traces, or reflected payloads in responses. It also
includes a small time-based blind injection probe (see TIME_BASED_PAYLOADS
below) that compares response latency against a clean baseline to catch
cases where no error/reflection is visible but the payload still executes.
"""
import time
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

# Time-based blind injection payloads: each one asks the backend to pause for
# TIME_DELAY_SECONDS. If the response takes meaningfully longer than a clean
# baseline request, that's strong evidence the payload reached a SQL engine or
# shell even though nothing came back in the response body (blind injection).
TIME_DELAY_SECONDS = 4
TIME_BASED_PAYLOADS = [
    (f"1' AND SLEEP({TIME_DELAY_SECONDS})-- -", "MySQL time-based blind SQL injection"),
    (f"1'; SELECT pg_sleep({TIME_DELAY_SECONDS})--", "PostgreSQL time-based blind SQL injection"),
    (f"1 WAITFOR DELAY '0:0:{TIME_DELAY_SECONDS}'--", "MSSQL time-based blind SQL injection"),
    (f"$(sleep {TIME_DELAY_SECONDS})", "OS command time-based blind injection"),
    (f"; sleep {TIME_DELAY_SECONDS}", "OS command time-based blind injection"),
]
# How much slower than baseline (in seconds) counts as suspicious.
TIME_DELTA_THRESHOLD = TIME_DELAY_SECONDS * 0.7


def _timed_request(client, ep: Endpoint, path: str, param_name: str, value):
    test_params = dict(ep.params)
    test_body = dict(ep.body) if ep.body else None
    if param_name in test_params:
        test_params[param_name] = value
    if test_body is not None and param_name in test_body:
        test_body[param_name] = value

    start = time.monotonic()
    try:
        resp = client.request(ep.method, path,
                               params=test_params if ep.method == "GET" else None,
                               json_body=test_body if ep.method in ("POST", "PUT", "PATCH") else None,
                               auth_override="keep")
    except Exception:
        return None, None
    return resp, time.monotonic() - start


def _check_time_based_blind(client, ep: Endpoint, path: str, label: str, param_name: str) -> list[Finding]:
    findings = []

    baseline_value = ep.params.get(param_name, ep.body.get(param_name) if ep.body else None) or "1"
    baseline_resp, baseline_elapsed = _timed_request(client, ep, path, param_name, baseline_value)
    if baseline_resp is None:
        return findings

    for payload, description in TIME_BASED_PAYLOADS:
        resp, elapsed = _timed_request(client, ep, path, param_name, payload)
        if resp is None:
            continue
        delta = elapsed - baseline_elapsed
        if delta >= TIME_DELTA_THRESHOLD and elapsed >= TIME_DELTA_THRESHOLD:
            findings.append(Finding(
                check="injection", severity=Severity.HIGH,
                title=f"Possible {description}",
                endpoint=label,
                detail=(f"Sending a time-delay payload into parameter '{param_name}' made the "
                        f"response take {elapsed:.1f}s vs a {baseline_elapsed:.1f}s baseline "
                        f"(+{delta:.1f}s) - consistent with the payload reaching a query/shell "
                        "even though no error or reflected content was visible in the response "
                        "(blind injection)."),
                evidence=f"payload={payload!r}, baseline={baseline_elapsed:.1f}s, delayed={elapsed:.1f}s",
                owasp_ref="API8:2023 Security Misconfiguration / Injection",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))
            break  # one confirmed hit per param is enough

    return findings


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

            # Time-based blind injection probe: only meaningful once per param
            # (it does its own baseline comparison), and deliberately kept
            # separate from the payload loop above since it adds latency.
            findings.extend(_check_time_based_blind(client, ep, path, label, param_name))

    return findings
