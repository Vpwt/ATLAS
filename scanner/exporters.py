"""Enterprise report exporters (JSON/CSV/JUnit/SARIF)."""
from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from scanner.models import Finding


def write_json_export(findings: list[Finding], base_url: str, output_path: str) -> None:
    payload = {
        "target": base_url,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "findings": [
            {
                "check": f.check,
                "severity": f.severity.value,
                "title": f.title,
                "endpoint": f.endpoint,
                "detail": f.detail,
                "evidence": f.evidence,
                "owasp_ref": f.owasp_ref,
                "cvss_score": f.cvss_score,
                "cwe": f.cwe,
                "remediation": f.remediation,
                "exploit_hint": f.exploit_hint,
                "curl_repro": f.curl_repro,
            }
            for f in findings
        ],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def write_csv_export(findings: list[Finding], output_path: str) -> None:
    fields = [
        "severity", "cvss_score", "check", "title", "endpoint", "detail",
        "evidence", "owasp_ref", "cwe", "remediation", "exploit_hint", "curl_repro",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for fd in findings:
            w.writerow({
                "severity": fd.severity.value,
                "cvss_score": fd.cvss_score,
                "check": fd.check,
                "title": fd.title,
                "endpoint": fd.endpoint,
                "detail": fd.detail,
                "evidence": fd.evidence,
                "owasp_ref": fd.owasp_ref,
                "cwe": fd.cwe,
                "remediation": fd.remediation,
                "exploit_hint": fd.exploit_hint,
                "curl_repro": fd.curl_repro,
            })


def write_junit_export(findings: list[Finding], output_path: str) -> None:
    suite = ET.Element("testsuite", {
        "name": "api-security-scan",
        "tests": str(max(1, len(findings))),
        "failures": str(len(findings)),
    })

    if not findings:
        case = ET.SubElement(suite, "testcase", {"name": "no-findings"})
        ET.SubElement(case, "system-out").text = "No findings produced by the checks that ran."
    else:
        for idx, f in enumerate(findings, start=1):
            case = ET.SubElement(suite, "testcase", {
                "name": f"{f.check}:{f.title}",
                "classname": "api-security",
                "time": "0",
            })
            failure = ET.SubElement(case, "failure", {
                "message": f"[{f.severity.value}] {f.title}",
                "type": f.check,
            })
            failure.text = f"Endpoint={f.endpoint}\nDetail={f.detail}\nEvidence={f.evidence}"
            ET.SubElement(case, "system-out").text = f.curl_repro or ""

    tree = ET.ElementTree(suite)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def write_sarif_export(findings: list[Finding], base_url: str, output_path: str) -> None:
    rules = {}
    results = []
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    for f in findings:
        rid = f.check
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": rid},
                "help": {"text": f.owasp_ref or "API scanner finding"},
            }

        results.append({
            "ruleId": rid,
            "level": level_map.get(f.severity.value, "warning"),
            "message": {"text": f"[{f.severity.value}] {f.title} @ {f.endpoint}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": base_url + f.endpoint.split(" ", 1)[-1]}
                }
            }],
            "properties": {
                "cvss": f.cvss_score,
                "evidence": f.evidence,
                "detail": f.detail,
                "cwe": f.cwe,
                "remediation": f.remediation,
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "API Security Scanner", "rules": list(rules.values())}},
            "results": results,
        }],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
