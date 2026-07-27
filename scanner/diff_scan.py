"""Differential scan snapshots and comparison utilities."""
from __future__ import annotations

import json
from datetime import datetime

from scanner.models import Endpoint, Finding


def save_snapshot(path: str, base_url: str, endpoints: list[Endpoint], findings: list[Finding]) -> None:
    payload = {
        "base_url": base_url,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "endpoints": sorted([f"{ep.method.upper()} {ep.path}" for ep in endpoints]),
        "findings": sorted([
            {
                "check": f.check,
                "severity": f.severity.value,
                "title": f.title,
                "endpoint": f.endpoint,
            }
            for f in findings
        ], key=lambda x: (x["endpoint"], x["check"], x["title"])),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def load_snapshot(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_snapshots(previous: dict, current: dict) -> dict:
    prev_eps = set(previous.get("endpoints") or [])
    cur_eps = set(current.get("endpoints") or [])

    def fkey(row: dict) -> tuple[str, str, str]:
        return (row.get("endpoint", ""), row.get("check", ""), row.get("title", ""))

    prev_find = {fkey(x): x for x in (previous.get("findings") or [])}
    cur_find = {fkey(x): x for x in (current.get("findings") or [])}

    new_keys = sorted(k for k in cur_find if k not in prev_find)
    resolved_keys = sorted(k for k in prev_find if k not in cur_find)

    return {
        "new_endpoints": sorted(cur_eps - prev_eps),
        "removed_endpoints": sorted(prev_eps - cur_eps),
        "new_findings": [cur_find[k] for k in new_keys],
        "resolved_findings": [prev_find[k] for k in resolved_keys],
    }
