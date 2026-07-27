"""API9:2023 - Improper Inventory Management.

Probes a short list of common paths for exposed API documentation, debug
endpoints, admin panels, and version-control/environment files that
shouldn't be publicly reachable, plus "shadow" API version prefixes
(older/newer siblings of the versions actually configured) that may still
be running less-hardened code. Also does lightweight passive discovery by
parsing robots.txt/sitemap.xml for paths that aren't in the configured
endpoint list - this is NOT a full crawler (no JS rendering / link
following), just cheap, commonly-available hints.
"""
import re
from scanner.models import Endpoint, Finding, Severity

# path -> (severity if exposed, human-readable reason)
PROBE_PATHS = {
    "/.env": (Severity.CRITICAL, "environment file (may contain secrets/credentials)"),
    "/.git/config": (Severity.CRITICAL, "exposed git repository metadata"),
    "/swagger.json": (Severity.LOW, "exposed OpenAPI/Swagger spec"),
    "/swagger-ui/": (Severity.LOW, "exposed Swagger UI"),
    "/openapi.json": (Severity.LOW, "exposed OpenAPI spec"),
    "/actuator": (Severity.MEDIUM, "exposed Spring Boot Actuator base"),
    "/actuator/env": (Severity.CRITICAL, "exposed Spring Boot Actuator env (may leak secrets)"),
    "/actuator/health": (Severity.LOW, "exposed Spring Boot Actuator health endpoint"),
    "/debug": (Severity.HIGH, "exposed debug endpoint"),
    "/graphql": (Severity.INFO, "GraphQL endpoint present - verify introspection is disabled in production"),
    "/server-status": (Severity.MEDIUM, "exposed Apache server-status page"),
}

_VERSION_RE = re.compile(r"^(/api)?/v(\d+)(/.*)?$")


def _shadow_version_paths(endpoints):
    """If configured endpoints use a versioned prefix like /api/v2/..., suggest
    checking whether older/newer sibling versions are still reachable."""
    candidates = set()
    for ep in endpoints:
        m = _VERSION_RE.match(ep.path)
        if not m:
            continue
        api_prefix, version, rest = m.groups()
        version_num = int(version)
        for alt in (version_num - 1, version_num + 1):
            if alt > 0:
                candidates.add(f"{api_prefix or ''}/v{alt}{rest or ''}")
    return candidates


def _paths_from_robots(text: str) -> set:
    return {m.group(1) for m in re.finditer(r"(?im)^(?:Disallow|Allow):\s*(/\S*)", text)}


def _paths_from_sitemap(text: str) -> set:
    paths = set()
    for m in re.finditer(r"<loc>\s*([^<]+)\s*</loc>", text, re.IGNORECASE):
        url = m.group(1).strip()
        path = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+", "", url)
        if path:
            paths.add(path)
    return paths


def _paths_from_html_links(html: str) -> set:
    paths = set()
    for m in re.finditer(r"(?i)(?:href|src)=['\"]([^'\"]+)['\"]", html or ""):
        ref = (m.group(1) or "").strip()
        if ref.startswith("/"):
            paths.add(ref)
    return paths


def _api_like_paths_from_js(js_text: str) -> set:
    paths = set()
    pattern = re.compile(r"['\"](/(?:api|graphql|v\d+)[^'\"\s]*)['\"]", re.IGNORECASE)
    for m in pattern.finditer(js_text or ""):
        paths.add(m.group(1))
    return paths


def run(client, endpoints: list[Endpoint]) -> list[Finding]:
    findings = []

    probe_paths = dict(PROBE_PATHS)
    for shadow_path in _shadow_version_paths(endpoints):
        probe_paths.setdefault(
            shadow_path,
            (Severity.MEDIUM, "possible unversioned/shadow API path still reachable"),
        )

    for probe_path, (severity, reason) in probe_paths.items():
        try:
            resp = client.request("GET", probe_path, auth_override="strip")
        except Exception:
            continue

        if resp.status_code < 400:
            findings.append(Finding(
                check="api_inventory", severity=severity,
                title=f"Potentially sensitive path is reachable: {probe_path}",
                endpoint=f"GET {probe_path}",
                detail=f"Unauthenticated GET to '{probe_path}' returned a non-error status - {reason}.",
                evidence=f"HTTP {resp.status_code}",
                owasp_ref="API9:2023 Improper Inventory Management",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))

    # Passive discovery: robots.txt / sitemap.xml, plus lightweight HTML/script
    # scraping for additional API-like paths.
    discovered_paths = set()
    for meta_path, parser in (("/robots.txt", _paths_from_robots), ("/sitemap.xml", _paths_from_sitemap)):
        try:
            resp = client.request("GET", meta_path, auth_override="strip")
        except Exception:
            continue
        if resp.status_code < 300 and resp.text:
            discovered_paths |= parser(resp.text)

    try:
        home = client.request("GET", "/", auth_override="strip")
    except Exception:
        home = None
    if home is not None and home.status_code < 300 and home.text:
        html_paths = _paths_from_html_links(home.text)
        discovered_paths |= {p for p in html_paths if p.startswith("/api") or p.startswith("/graphql")}

        # Pull linked JS files and mine API-like route strings.
        for script_path in [p for p in html_paths if p.endswith(".js")][:20]:
            try:
                script_resp = client.request("GET", script_path, auth_override="strip")
            except Exception:
                continue
            if script_resp.status_code < 300 and script_resp.text:
                discovered_paths |= _api_like_paths_from_js(script_resp.text)

    known_paths = {ep.path for ep in endpoints}
    for path in discovered_paths - known_paths:
        try:
            resp = client.request("GET", path, auth_override="strip")
        except Exception:
            continue
        if resp.status_code < 400:
            findings.append(Finding(
                check="api_inventory", severity=Severity.LOW,
                title=f"Undocumented path discovered via robots.txt/sitemap.xml: {path}",
                endpoint=f"GET {path}",
                detail=(f"'{path}' was found listed in robots.txt or sitemap.xml and isn't part "
                        "of the configured endpoint list, but responded with a non-error status. "
                        "Confirm it's intended to be publicly reachable and covered by the same "
                        "security controls as documented endpoints."),
                evidence=f"HTTP {resp.status_code}",
                owasp_ref="API9:2023 Improper Inventory Management",
                curl_repro=getattr(resp, "curl_repro", ""),
            ))

    return findings
