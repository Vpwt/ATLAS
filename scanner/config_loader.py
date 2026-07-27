"""Loads scan configuration (target, auth, endpoints) from a YAML file."""
import yaml
from scanner.models import Endpoint
from scanner.openapi_loader import load_endpoints_from_spec
from scanner.postman_loader import load_endpoints_from_postman


def _endpoint_from_raw(ep_raw: dict) -> Endpoint:
    return Endpoint(
        path=ep_raw["path"],
        method=ep_raw.get("method", "GET").upper(),
        auth_required=ep_raw.get("auth_required", True),
        params=ep_raw.get("params", {}) or {},
        body=ep_raw.get("body"),
        id_param=ep_raw.get("id_param"),
        sample_ids=ep_raw.get("sample_ids", []) or [],
        foreign_ids=ep_raw.get("foreign_ids", []) or [],
        admin_only=ep_raw.get("admin_only", False),
        description=ep_raw.get("description", ""),
    )


def _apply_override(base: Endpoint, ep_raw: dict) -> None:
    """Apply only the fields explicitly present in `ep_raw` onto `base`, in place.

    Used to layer manually-configured details (most importantly the
    `sample_ids` / `foreign_ids` / `id_param` needed for BOLA testing, which
    an OpenAPI spec has no way of expressing) onto an endpoint that was
    auto-discovered from an OpenAPI/Swagger spec.
    """
    if "auth_required" in ep_raw:
        base.auth_required = ep_raw["auth_required"]
    if ep_raw.get("params"):
        base.params.update(ep_raw["params"])
    if "body" in ep_raw:
        base.body = ep_raw["body"]
    if "id_param" in ep_raw:
        base.id_param = ep_raw["id_param"]
    if ep_raw.get("sample_ids"):
        base.sample_ids = ep_raw["sample_ids"]
    if ep_raw.get("foreign_ids"):
        base.foreign_ids = ep_raw["foreign_ids"]
    if "admin_only" in ep_raw:
        base.admin_only = ep_raw["admin_only"]
    if ep_raw.get("description"):
        base.description = ep_raw["description"]


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)

    endpoint_overrides = raw.get("endpoints", []) or []
    spec_source = raw.get("openapi_spec")
    postman_source = raw.get("postman_collection")

    if spec_source:
        discovered = load_endpoints_from_spec(spec_source)
    elif postman_source:
        discovered = load_endpoints_from_postman(postman_source)
    else:
        discovered = None

    if discovered is not None:
        by_key = {(e.method, e.path): e for e in discovered}
        for ep_raw in endpoint_overrides:
            key = (ep_raw.get("method", "GET").upper(), ep_raw["path"])
            base = by_key.get(key)
            if base is not None:
                _apply_override(base, ep_raw)
            else:
                # Not present in the spec/collection (e.g. undocumented endpoint) - add as-is.
                discovered.append(_endpoint_from_raw(ep_raw))
        endpoints = discovered
    else:
        endpoints = [_endpoint_from_raw(ep_raw) for ep_raw in endpoint_overrides]

    return {
        "base_url": raw["base_url"],
        "auth_header": raw.get("auth_header"),   # e.g. "Bearer abc123"
        "jwt_sample_token": raw.get("jwt_sample_token"),
        # Optional public key material for the JWT check's RS256->HS256
        # algorithm-confusion attack: either paste the PEM directly
        # (jwt_public_key) or point at a JWKS endpoint to fetch it from
        # (jwks_url). Not needed for HS256-signed tokens.
        "jwt_public_key": raw.get("jwt_public_key"),
        "jwks_url": raw.get("jwks_url"),
        # Optional attacker-controlled callback/collaborator URL (e.g. a
        # webhook.site URL) used by the ssrf check to confirm true
        # out-of-band SSRF when the HTTP response gives no visible signal.
        "ssrf_callback_url": raw.get("ssrf_callback_url"),
        # Optional automated login: instead of pasting a static auth_header,
        # perform a login request and extract a bearer token from it. See
        # scanner/auth_flow.py for the expected fields.
        "login": raw.get("login"),
        # Optional GraphQL endpoint (e.g. "/graphql") to run introspection /
        # sensitive-mutation-discovery checks against. Off by default.
        "graphql_endpoint": raw.get("graphql_endpoint"),
        # Optional list of multi-step business-logic workflows to replay (see
        # scanner/checks/business_logic.py for the schema).
        "workflows": raw.get("workflows", []) or [],
        # Optional second, lower-privileged test account token, used by the bfla
        # check to confirm admin-only endpoints reject non-admin users too.
        "low_priv_auth_header": raw.get("low_priv_auth_header"),
        # Verb-tampering tests (trying undeclared HTTP methods against a path)
        # can hit destructive verbs like DELETE/PUT, so they're opt-in.
        "enable_verb_tampering": raw.get("enable_verb_tampering", False),
        "request_delay": raw.get("request_delay", 0.1),
        "rate_limit_burst": raw.get("rate_limit_burst", 25),
        "verify_tls": raw.get("verify_tls", True),
        "endpoints": endpoints,
    }
