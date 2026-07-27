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

BOOLEAN_TESTS = [
    ("1' AND '1'='1", "1' AND '1'='2", "SQL boolean-based injection"),
    ("1 OR 1=1", "1 OR 1=2", "SQL boolean-based injection"),
    ("true || true", "true || false", "NoSQL boolean-based injection"),
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
TIME_DELAYS = (2, 4, 6)
# How much slower than baseline (in seconds) counts as suspicious.
TIME_DELTA_THRESHOLD_FACTOR = 0.7


def _build_time_based_payloads(delay_seconds: int) -> list[tuple[str, str]]:
    return [
        (f"1' AND SLEEP({delay_seconds})-- -", "MySQL time-based blind SQL injection"),
        (f"1'; SELECT pg_sleep({delay_seconds})--", "PostgreSQL time-based blind SQL injection"),
        (f"1 WAITFOR DELAY '0:0:{delay_seconds}'--", "MSSQL time-based blind SQL injection"),
        (f"$(sleep {delay_seconds})", "OS command time-based blind injection"),
        (f"; sleep {delay_seconds}", "OS command time-based blind injection"),
    ]


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
                               auth_override="keep",
                               body_content_type=ep.body_content_type)
    except Exception:
        return None, None
    return resp, time.monotonic() - start


def _check_time_based_blind(client, ep: Endpoint, path: str, label: str, param_name: str) -> list[Finding]:
    findings = []

    baseline_value = ep.params.get(param_name, ep.body.get(param_name) if ep.body else None) or "1"
    baseline_resp, baseline_elapsed = _timed_request(client, ep, path, param_name, baseline_value)
    if baseline_resp is None:
        return findings

    for delay_seconds in TIME_DELAYS:
        threshold = delay_seconds * TIME_DELTA_THRESHOLD_FACTOR
        for payload, description in _build_time_based_payloads(delay_seconds):
            resp, elapsed = _timed_request(client, ep, path, param_name, payload)
            if resp is None:
                continue
            delta = elapsed - baseline_elapsed
            if delta >= threshold and elapsed >= threshold:
                findings.append(Finding(
                    check="injection", severity=Severity.HIGH,
                    title=f"Possible {description}",
                    endpoint=label,
                    detail=(f"Sending a time-delay payload into parameter '{param_name}' made the "
                            f"response take {elapsed:.1f}s vs a {baseline_elapsed:.1f}s baseline "
                            f"(+{delta:.1f}s) - consistent with the payload reaching a query/shell "
                            "even though no error or reflected content was visible in the response "
                            "(blind injection)."),
                    evidence=(f"payload={payload!r}, baseline={baseline_elapsed:.1f}s, "
                              f"delayed={elapsed:.1f}s, delay_target={delay_seconds}s"),
                    owasp_ref="API8:2023 Security Misconfiguration / Injection",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
                return findings  # one confirmed hit per param is enough

    return findings


def _check_boolean_blind(client, ep: Endpoint, path: str, label: str, param_name: str) -> list[Finding]:
    findings = []
    for true_payload, false_payload, description in BOOLEAN_TESTS:
        true_params = dict(ep.params)
        false_params = dict(ep.params)
        true_params[param_name] = true_payload
        false_params[param_name] = false_payload

        try:
            resp_true = client.request(
                ep.method,
                path,
                params=true_params if ep.method == "GET" else None,
                json_body={**(ep.body or {}), param_name: true_payload}
                if ep.method in ("POST", "PUT", "PATCH") else None,
                auth_override="keep",
                body_content_type=ep.body_content_type,
            )
            resp_false = client.request(
                ep.method,
                path,
                params=false_params if ep.method == "GET" else None,
                json_body={**(ep.body or {}), param_name: false_payload}
                if ep.method in ("POST", "PUT", "PATCH") else None,
                auth_override="keep",
                body_content_type=ep.body_content_type,
            )
        except Exception:
            continue

        true_len = len(resp_true.text or "")
        false_len = len(resp_false.text or "")
        if resp_true.status_code != resp_false.status_code or abs(true_len - false_len) > max(40, int(0.2 * max(true_len, false_len, 1))):
            findings.append(Finding(
                check="injection", severity=Severity.MEDIUM,
                title=f"Possible {description}",
                endpoint=label,
                detail=(f"Boolean true/false payloads in '{param_name}' produced meaningfully "
                        "different responses. This can indicate blind injection behavior when "
                        "error signatures are absent."),
                evidence=(f"true_status={resp_true.status_code}, false_status={resp_false.status_code}, "
                          f"true_len={true_len}, false_len={false_len}"),
                owasp_ref="API8:2023 Security Misconfiguration / Injection",
                curl_repro=getattr(resp_true, "curl_repro", ""),
            ))
            break
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
                                           auth_override="keep",
                                           body_content_type=ep.body_content_type)
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
            findings.extend(_check_boolean_blind(client, ep, path, label, param_name))
            findings.extend(_check_time_based_blind(client, ep, path, label, param_name))

    return findings
