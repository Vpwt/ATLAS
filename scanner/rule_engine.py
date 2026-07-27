"""YAML-defined detection rules executed as scanner checks."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from scanner.models import Endpoint, Finding, Severity


def _parse_severity(value: str) -> Severity:
    raw = (value or "MEDIUM").upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }.get(raw, Severity.MEDIUM)


def load_rule_files(rules_dir: str) -> list[dict[str, Any]]:
    root = Path(rules_dir)
    if not root.exists() or not root.is_dir():
        return []

    rules: list[dict[str, Any]] = []
    for file in sorted(root.glob("*.y*ml")):
        try:
            with file.open("r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
            for d in docs:
                if isinstance(d, dict):
                    d["__source_file"] = str(file)
                    rules.append(d)
        except Exception:
            continue
    return rules


def run_yaml_rules(client, endpoints: list[Endpoint], rules: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        rid = str(rule.get("id") or "unnamed-rule")
        sev = _parse_severity(str(rule.get("severity") or "MEDIUM"))
        request = rule.get("request") or {}
        match = rule.get("match") or {}

        method = str(request.get("method") or "GET").upper()
        path = str(request.get("path") or "/")
        body = request.get("body")
        params = request.get("params")
        auth_override = request.get("auth_override", "keep")

        # Only execute rule if the path exists in discovered/configured endpoints,
        # unless explicit run_when_missing=true is set.
        known_paths = {ep.path for ep in endpoints}
        if path not in known_paths and not bool(rule.get("run_when_missing", False)):
            continue

        try:
            resp = client.request(method, path, params=params, json_body=body, auth_override=auth_override)
        except Exception as e:
            findings.append(Finding(
                check="yaml_rules",
                severity=Severity.INFO,
                title=f"Rule execution error: {rid}",
                endpoint=f"{method} {path}",
                detail=f"Rule failed to execute request: {e}",
                evidence=f"source={rule.get('__source_file', '')}",
            ))
            continue

        expected_status = match.get("status")
        body_contains = match.get("body_contains")
        header_exists = match.get("header_exists")

        status_ok = True if expected_status is None else (resp.status_code == int(expected_status))
        body_ok = True
        if body_contains is not None:
            body_ok = str(body_contains) in (resp.text or "")

        header_ok = True
        if header_exists is not None:
            header_ok = any(k.lower() == str(header_exists).lower() for k in resp.headers.keys())

        if status_ok and body_ok and header_ok:
            findings.append(Finding(
                check="yaml_rules",
                severity=sev,
                title=str(rule.get("title") or f"Rule matched: {rid}"),
                endpoint=f"{method} {path}",
                detail=str(rule.get("description") or "YAML rule condition matched."),
                evidence=f"status={resp.status_code}; rule_id={rid}",
                owasp_ref=str(rule.get("owasp_ref") or ""),
                curl_repro=getattr(resp, "curl_repro", ""),
            ))

    return findings
