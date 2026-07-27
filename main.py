#!/usr/bin/env python3
"""
API Security Scanner
=====================
A lightweight scanner that probes a REST API you own/are authorized to test
for common issues aligned with the OWASP API Security Top 10.

Usage:
    python main.py --config config.yaml [--output report.html] [--checks auth,bola,injection]

WARNING: This tool sends live requests, including attack-style payloads
(injection strings, forged tokens, request bursts) to the target base_url.
Only run it against systems you own or have explicit written authorization
to test.
"""
import argparse
import asyncio
import json
import sys
import yaml

from scanner.config_loader import load_config
from scanner.http_client import ApiClient
from scanner.report import print_console_summary, write_html_report
from scanner.auth_flow import TokenRefresher
from scanner.async_engine import run_checks_async
from scanner.plugin_loader import load_plugins
from scanner.rule_engine import load_rule_files, run_yaml_rules
from scanner.proxy_mode import run_proxy_capture
from scanner.browser_discovery import discover_endpoints_with_playwright
from scanner.advanced_auth import build_auth_runtime
from scanner.exporters import write_json_export, write_csv_export, write_junit_export, write_sarif_export
from scanner.diff_scan import save_snapshot, load_snapshot, compare_snapshots
from scanner.risk_engine import build_risk_summary
from scanner.ai_assist import enrich_findings_with_assistance
from scanner.assurance import build_assurance_summary
from scanner.checks import (
    auth, bola, injection, rate_limit, headers, mass_assignment, jwt_checks,
    error_disclosure, bfla, ssrf, excessive_data_exposure, api_inventory, http_methods,
    graphql, business_logic, unsafe_consumption, fuzzing,
)

ALL_BUILTIN_CHECKS = {
    "auth": auth.run,
    "bola": bola.run,
    "bfla": bfla.run,
    "injection": injection.run,
    "ssrf": ssrf.run,
    "rate_limit": rate_limit.run,
    "headers": headers.run,
    "http_methods": http_methods.run,
    "mass_assignment": mass_assignment.run,
    "excessive_data_exposure": excessive_data_exposure.run,
    "jwt": jwt_checks.run,
    "error_disclosure": error_disclosure.run,
    "api_inventory": api_inventory.run,
    "graphql": graphql.run,
    "business_logic": business_logic.run,
    "unsafe_consumption": unsafe_consumption.run,
    "fuzzing": fuzzing.run,
}


def confirm_authorization(base_url: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    print(f"\nYou are about to run active security tests against: {base_url}")
    print("This includes injection payloads, auth bypass attempts, forged tokens,")
    print("and request bursts. Only proceed if you own this system or have explicit")
    print("written authorization to test it.\n")
    answer = input("Type YES to confirm you are authorized to test this target: ")
    return answer.strip() == "YES"


def main():
    parser = argparse.ArgumentParser(description="API Security Scanner (OWASP API Top 10 aligned)")
    parser.add_argument("--config", required=False, help="Path to YAML config file describing the target/endpoints")
    parser.add_argument("--base-url", default=None, help="Override base URL (or set one for capture/discovery modes)")
    parser.add_argument("--output", default="report.html", help="Path to write the HTML report")
    parser.add_argument("--checks", default=None,
                         help=f"Comma-separated list of checks to run. Default: all. Built-ins: {', '.join(ALL_BUILTIN_CHECKS)}")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation prompt")
    parser.add_argument("--engine", choices=("sync", "async"), default="async",
                        help="Execution engine for check modules. 'async' runs checks concurrently.")
    parser.add_argument("--check-concurrency", type=int, default=4,
                        help="Maximum number of checks to run in parallel when --engine=async")
    parser.add_argument("--plugins-dir", default="plugins", help="Directory containing external plugin checks")
    parser.add_argument("--disable-plugins", action="store_true", help="Disable external plugin loading")
    parser.add_argument("--rules-dir", default="rules", help="Directory containing YAML detection rules")
    parser.add_argument("--disable-rules", action="store_true", help="Disable YAML detection rules")

    parser.add_argument("--proxy-mode", action="store_true",
                        help="Run reverse-proxy capture mode and generate a config from observed traffic")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Host to bind proxy capture mode")
    parser.add_argument("--proxy-port", type=int, default=8081, help="Port to bind proxy capture mode")
    parser.add_argument("--proxy-output", default="captured_config.yaml",
                        help="Output config path written when proxy mode stops")

    parser.add_argument("--browser-discovery-url", default=None,
                        help="Start URL for Playwright browser discovery mode")
    parser.add_argument("--browser-discovery-seconds", type=int, default=60,
                        help="How long to capture browser API traffic in discovery mode")
    parser.add_argument("--browser-discovery-output", default="browser_discovered_config.yaml",
                        help="Output config path generated by browser discovery")
    parser.add_argument("--browser-include-third-party", action="store_true",
                        help="Include third-party API hosts during browser discovery")
    parser.add_argument("--browser-autonomous", action="store_true",
                        help="Enable bounded autonomous crawler mode for browser discovery")
    parser.add_argument("--browser-max-pages", type=int, default=20,
                        help="Maximum pages for autonomous browser discovery")
    parser.add_argument("--browser-max-clicks-per-page", type=int, default=6,
                        help="Maximum click interactions per page in autonomous mode")
    parser.add_argument("--browser-login-url", default="", help="Optional login URL for browser discovery auth")
    parser.add_argument("--browser-login-username", default="", help="Username for browser discovery login")
    parser.add_argument("--browser-login-password", default="", help="Password for browser discovery login")
    parser.add_argument("--browser-username-selector", default="", help="CSS selector for username input")
    parser.add_argument("--browser-password-selector", default="", help="CSS selector for password input")
    parser.add_argument("--browser-submit-selector", default="", help="CSS selector for login submit control")
    parser.add_argument("--export-json", default="", help="Optional path to write JSON findings export")
    parser.add_argument("--export-csv", default="", help="Optional path to write CSV findings export")
    parser.add_argument("--export-junit", default="", help="Optional path to write JUnit XML findings export")
    parser.add_argument("--export-sarif", default="", help="Optional path to write SARIF findings export")
    parser.add_argument("--snapshot-file", default="", help="Optional path to write a scan snapshot JSON")
    parser.add_argument("--diff-against", default="", help="Optional previous snapshot path for differential output")
    parser.add_argument("--diff-output", default="scan_diff.json", help="Path to write differential report JSON when --diff-against is set")
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    base_url = args.base_url or config.get("base_url")

    if args.proxy_mode:
        if not base_url:
            print("Proxy mode requires --base-url or a config containing base_url.")
            sys.exit(1)
        run_proxy_capture(args.proxy_host, args.proxy_port, base_url, args.proxy_output)
        return

    if args.browser_discovery_url:
        discovered = asyncio.run(discover_endpoints_with_playwright(
            args.browser_discovery_url,
            capture_seconds=args.browser_discovery_seconds,
            include_third_party=args.browser_include_third_party,
            autonomous=args.browser_autonomous,
            max_pages=args.browser_max_pages,
            max_clicks_per_page=args.browser_max_clicks_per_page,
            login_url=args.browser_login_url or None,
            username=args.browser_login_username,
            password=args.browser_login_password,
            username_selector=args.browser_username_selector,
            password_selector=args.browser_password_selector,
            submit_selector=args.browser_submit_selector,
        ))
        generated = {
            "base_url": base_url or args.browser_discovery_url,
            "auth_header": "",
            "request_delay": 0.1,
            "rate_limit_burst": 25,
            "verify_tls": True,
            "endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "auth_required": ep.auth_required,
                    "params": ep.params,
                    "body": ep.body,
                    "description": ep.description,
                }
                for ep in discovered
            ],
        }
        with open(args.browser_discovery_output, "w", encoding="utf-8") as f:
            yaml.safe_dump(generated, f, sort_keys=False)
        print(f"Discovered {len(discovered)} endpoints via browser traffic.")
        print(f"Generated config written to: {args.browser_discovery_output}")
        return

    if not config:
        print("Standard scan mode requires --config.")
        sys.exit(1)

    if not confirm_authorization(base_url, args.yes):
        print("Authorization not confirmed. Exiting without running any tests.")
        sys.exit(1)

    auth_runtime = build_auth_runtime(base_url, config, verify_tls=config.get("verify_tls", True))
    default_headers = dict(auth_runtime.default_headers)
    auth_provider = auth_runtime.auth_provider

    login_config = config.get("login")
    if login_config:
        refresher = TokenRefresher(
            base_url, login_config,
            verify_tls=config.get("verify_tls", True),
            refresh_interval=login_config.get("refresh_interval", 0),
        )
        try:
            default_headers["Authorization"] = refresher.get_token()
            print(f"Logged in automatically via {login_config['url']} to obtain a fresh auth token.")
            if login_config.get("refresh_interval") or auth_provider is None:
                auth_provider = refresher.get_token  # re-fetch periodically during the scan
        except Exception as e:
            print(f"Warning: automatic login failed ({e}); falling back to auth_header if configured.")

    client = ApiClient(
        base_url=base_url,
        default_headers=default_headers,
        verify_tls=config.get("verify_tls", True),
        request_delay=config.get("request_delay", 0.1),
        auth_provider=auth_provider,
        session_cookie=auth_runtime.session_cookie,
        signer=auth_runtime.signer,
        client_cert=auth_runtime.client_cert,
    )

    all_checks = dict(ALL_BUILTIN_CHECKS)

    if not args.disable_plugins:
        plugin_checks, plugin_notes = load_plugins(args.plugins_dir)
        for note in plugin_notes:
            print(f"[plugin] {note}")
        all_checks.update(plugin_checks)

    yaml_rules = []
    if not args.disable_rules:
        yaml_rules = load_rule_files(args.rules_dir)
        if yaml_rules:
            all_checks["yaml_rules"] = run_yaml_rules
            print(f"[rules] loaded {len(yaml_rules)} YAML detection rule(s) from {args.rules_dir}")

    checks_to_run = list(all_checks)
    if args.checks:
        requested = [c.strip() for c in args.checks.split(",")]
        unknown = [c for c in requested if c not in all_checks]
        if unknown:
            print(f"Unknown check(s): {', '.join(unknown)}. Available: {', '.join(all_checks)}")
            sys.exit(1)
        checks_to_run = requested

    endpoints = config["endpoints"]
    if not endpoints:
        print("No endpoints defined in config file. Nothing to scan.")
        sys.exit(1)

    all_findings = []
    print(f"\nScanning {base_url} ({len(endpoints)} endpoint(s), {len(checks_to_run)} check module(s))...\n")

    def run_one_check_sync(check_name: str):
        print(f"  -> running check: {check_name}")
        fn = all_checks[check_name]
        try:
            if check_name == "rate_limit":
                findings = fn(client, endpoints, burst_count=config.get("rate_limit_burst", 25))
            elif check_name == "jwt":
                findings = fn(client, endpoints, jwt_sample_token=config.get("jwt_sample_token"),
                              jwt_public_key=config.get("jwt_public_key"),
                              jwks_url=config.get("jwks_url"),
                              jwt_secret_wordlist=config.get("jwt_secret_wordlist"))
            elif check_name == "bfla":
                findings = fn(client, endpoints,
                              low_priv_auth_header=config.get("low_priv_auth_header"),
                              enable_verb_tampering=config.get("enable_verb_tampering", False),
                              verb_tampering_mode=config.get("verb_tampering_mode", "safe"))
            elif check_name == "graphql":
                findings = fn(client, endpoints, graphql_path=config.get("graphql_endpoint"))
            elif check_name == "business_logic":
                findings = fn(
                    client,
                    config.get("workflows", []),
                    max_skip_combo_size=config.get("business_logic_max_skip_combo_size", 3),
                    max_reorder_steps=config.get("business_logic_max_reorder_steps", 5),
                    max_reorder_permutations=config.get("business_logic_max_reorder_permutations", 30),
                )
            elif check_name == "ssrf":
                findings = fn(
                    client,
                    endpoints,
                    ssrf_callback_url=config.get("ssrf_callback_url"),
                    ssrf_callback_verify_url=config.get("ssrf_callback_verify_url"),
                )
            elif check_name == "yaml_rules":
                findings = fn(client, endpoints, yaml_rules)
            else:
                try:
                    findings = fn(client, endpoints, config=config)
                except TypeError:
                    findings = fn(client, endpoints)
        except Exception as e:
            print(f"     check '{check_name}' raised an error: {e}")
            findings = []
        return findings

    if args.engine == "async":
        all_findings = asyncio.run(run_checks_async(
            checks_to_run,
            all_checks,
            run_one_check_sync,
            concurrency=args.check_concurrency,
        ))
    else:
        for check_name in checks_to_run:
            all_findings.extend(run_one_check_sync(check_name))

    print(f"\nTotal requests sent: {client.request_count}")
    all_findings = enrich_findings_with_assistance(all_findings)

    risk_summary = build_risk_summary(all_findings)
    assurance_summary = build_assurance_summary(endpoints, all_findings, checks_to_run)
    print("\nRisk summary")
    print(f"  Risk score: {risk_summary['risk_score']}/100")
    if risk_summary["attack_chains"]:
        print(f"  Attack chains: {len(risk_summary['attack_chains'])}")
    print("\nAssurance summary")
    print(f"  Confidence score: {assurance_summary['confidence_score']}/100")
    print(f"  Endpoint coverage (observed): {assurance_summary['coverage_percent']}%")
    print(
        "  Formal guarantee: "
        f"true high/critical endpoint rate <= {assurance_summary['proof_upper_bound_fail_percent']}% "
        f"with confidence {assurance_summary['proof_confidence_percent']}%"
    )
    print(f"  Stance: {assurance_summary['stance']}")

    print_console_summary(all_findings, base_url)
    write_html_report(
        all_findings,
        base_url,
        args.output,
        endpoints=endpoints,
        risk_summary=risk_summary,
        assurance_summary=assurance_summary,
    )
    print(f"HTML report written to: {args.output}")

    if args.export_json:
        write_json_export(all_findings, base_url, args.export_json)
        print(f"JSON export written to: {args.export_json}")
    if args.export_csv:
        write_csv_export(all_findings, args.export_csv)
        print(f"CSV export written to: {args.export_csv}")
    if args.export_junit:
        write_junit_export(all_findings, args.export_junit)
        print(f"JUnit export written to: {args.export_junit}")
    if args.export_sarif:
        write_sarif_export(all_findings, base_url, args.export_sarif)
        print(f"SARIF export written to: {args.export_sarif}")

    snapshot_payload = None
    if args.snapshot_file:
        save_snapshot(args.snapshot_file, base_url, endpoints, all_findings)
        print(f"Snapshot written to: {args.snapshot_file}")
        snapshot_payload = load_snapshot(args.snapshot_file)

    if args.diff_against:
        previous = load_snapshot(args.diff_against)
        if snapshot_payload is None:
            snapshot_payload = {
                "base_url": base_url,
                "endpoints": sorted([f"{ep.method.upper()} {ep.path}" for ep in endpoints]),
                "findings": [
                    {"check": f.check, "severity": f.severity.value, "title": f.title, "endpoint": f.endpoint}
                    for f in all_findings
                ],
            }
        diff = compare_snapshots(previous, snapshot_payload)
        with open(args.diff_output, "w", encoding="utf-8") as f:
            json.dump(diff, f, indent=2)
        print(f"Diff report written to: {args.diff_output}")
        print(f"  New endpoints: {len(diff['new_endpoints'])}, removed endpoints: {len(diff['removed_endpoints'])}")
        print(f"  New findings: {len(diff['new_findings'])}, resolved findings: {len(diff['resolved_findings'])}")

    client.close()


if __name__ == "__main__":
    main()
