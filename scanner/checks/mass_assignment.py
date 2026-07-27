"""API6:2023 - Unrestricted Access to Sensitive Business Flows / Mass Assignment.

Sends extra, unexpected fields in write requests (POST/PUT/PATCH) to see if
the API blindly accepts and stores fields it shouldn't (e.g. 'is_admin',
'role', 'balance') - classic mass assignment.
"""
from scanner.models import Endpoint, Finding, Severity

SENSITIVE_EXTRA_FIELDS = {
    "is_admin": True,
    "role": "admin",
    "isAdmin": True,
    "account_balance": 999999,
    "verified": True,
    "credit": 999999,
}


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    for ep in endpoints:
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue

        path = ep.resolved_path()
        label = f"{ep.method} {path}"
        base_body = dict(ep.body or {})
        injected_body = {**base_body, **SENSITIVE_EXTRA_FIELDS}

        try:
            resp = client.request(ep.method, path, json_body=injected_body, auth_override="keep",
                                   body_content_type=ep.body_content_type)
        except Exception:
            continue

        if resp.status_code >= 400:
            continue  # rejected outright, good sign

        # Try to see if any injected field got reflected back as accepted/stored
        try:
            response_json = resp.json()
        except ValueError:
            response_json = {}

        reflected = [f for f in SENSITIVE_EXTRA_FIELDS if _field_present(response_json, f)]

        if reflected:
            findings.append(Finding(
                check="mass_assignment", severity=Severity.HIGH,
                title="Possible mass assignment: sensitive fields accepted",
                endpoint=label,
                detail=(f"Sent unexpected sensitive fields ({', '.join(reflected)}) in the request "
                        "body and they appear reflected/stored in the response. Ensure the API "
                        "uses an explicit allow-list for writable fields rather than binding the "
                        "full request body to internal models."),
                evidence=f"Reflected fields: {reflected}",
                owasp_ref="API6:2023 Unrestricted Access to Sensitive Business Flows",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))
        elif resp.status_code < 300:
            findings.append(Finding(
                check="mass_assignment", severity=Severity.LOW,
                title="Write request with extra unexpected fields was accepted",
                endpoint=label,
                detail=("The request succeeded even though extra, unrequested fields were "
                        "included. Response didn't clearly reflect them, but manual review is "
                        "recommended to confirm the fields weren't silently applied."),
                evidence=f"HTTP {resp.status_code}",
                owasp_ref="API6:2023 Unrestricted Access to Sensitive Business Flows",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))

    return findings


def _field_present(obj, field_name) -> bool:
    if isinstance(obj, dict):
        if field_name in obj:
            return True
        return any(_field_present(v, field_name) for v in obj.values())
    if isinstance(obj, list):
        return any(_field_present(v, field_name) for v in obj)
    return False
