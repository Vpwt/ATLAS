"""API3:2023 - Broken Object Property Level Authorization (excessive data exposure).

Sends a normal authenticated GET request and scans the JSON response for
sensitive-looking fields (password hashes, secrets, tokens, PII) that
probably shouldn't be returned to a regular client at all, regardless of
what was actually requested. This catches APIs that dump full internal
objects and rely on the client to only display the "safe" fields.
"""
from scanner.models import Endpoint, Finding, Severity

SENSITIVE_FIELD_NAMES = (
    "password", "passwd", "password_hash", "hashed_password", "secret",
    "api_key", "apikey", "private_key", "access_token", "refresh_token",
    "ssn", "social_security", "credit_card", "card_number", "cvv", "salt",
)


def _find_sensitive_fields(obj, found=None, path=""):
    if found is None:
        found = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_lower = str(key).lower()
            field_path = f"{path}.{key}".lstrip(".")
            if any(name in key_lower for name in SENSITIVE_FIELD_NAMES) and value not in (None, "", False):
                found[field_path] = value
            _find_sensitive_fields(value, found, field_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _find_sensitive_fields(item, found, f"{path}[{i}]")
    return found


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if ep.method != "GET":
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"

        try:
            resp = client.request(ep.method, path, params=ep.params, auth_override="keep")
        except Exception:
            continue

        if resp.status_code >= 300:
            continue

        try:
            response_json = resp.json()
        except ValueError:
            continue

        sensitive = _find_sensitive_fields(response_json)
        if sensitive:
            field_names = list(sensitive)[:5]
            sample = {k: sensitive[k] for k in field_names}
            findings.append(Finding(
                check="excessive_data_exposure", severity=Severity.HIGH,
                title="Response includes sensitive-looking fields",
                endpoint=label,
                detail=(f"The response body includes field(s) that look sensitive "
                        f"({', '.join(field_names)}). APIs should filter response payloads to "
                        "only the fields the client needs server-side, rather than relying on "
                        "the client to ignore extra data."),
                evidence=f"e.g. {sample}",
                owasp_ref="API3:2023 Broken Object Property Level Authorization",
            ))

    return findings
