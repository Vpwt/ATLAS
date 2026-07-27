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
import sys

from scanner.config_loader import load_config
from scanner.http_client import ApiClient
from scanner.report import print_console_summary, write_html_report
from scanner.auth_flow import TokenRefresher
from scanner.checks import (
    auth, bola, injection, rate_limit, headers, mass_assignment, jwt_checks,
    error_disclosure, bfla, ssrf, excessive_data_exposure, api_inventory, http_methods,
    graphql, business_logic,
)

ALL_CHECKS = {
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
    parser.add_argument("--config", required=True, help="Path to YAML config file describing the target/endpoints")
    parser.add_argument("--output", default="report.html", help="Path to write the HTML report")
    parser.add_argument("--checks", default=None,
                         help=f"Comma-separated list of checks to run. Default: all. Options: {', '.join(ALL_CHECKS)}")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization confirmation prompt")
    args = parser.parse_args()

    config = load_config(args.config)
    base_url = config["base_url"]

    if not confirm_authorization(base_url, args.yes):
        print("Authorization not confirmed. Exiting without running any tests.")
        sys.exit(1)

    default_headers = {}
    if config.get("auth_header"):
        default_headers["Authorization"] = config["auth_header"]

    auth_provider = None
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
            if login_config.get("refresh_interval"):
                auth_provider = refresher.get_token  # re-fetch periodically during the scan
        except Exception as e:
            print(f"Warning: automatic login failed ({e}); falling back to auth_header if configured.")

    client = ApiClient(
        base_url=base_url,
        default_headers=default_headers,
        verify_tls=config.get("verify_tls", True),
        request_delay=config.get("request_delay", 0.1),
        auth_provider=auth_provider,
    )

    checks_to_run = list(ALL_CHECKS)
    if args.checks:
        requested = [c.strip() for c in args.checks.split(",")]
        unknown = [c for c in requested if c not in ALL_CHECKS]
        if unknown:
            print(f"Unknown check(s): {', '.join(unknown)}. Available: {', '.join(ALL_CHECKS)}")
            sys.exit(1)
        checks_to_run = requested

    endpoints = config["endpoints"]
    if not endpoints:
        print("No endpoints defined in config file. Nothing to scan.")
        sys.exit(1)

    all_findings = []
    print(f"\nScanning {base_url} ({len(endpoints)} endpoint(s), {len(checks_to_run)} check module(s))...\n")

    for check_name in checks_to_run:
        print(f"  -> running check: {check_name}")
        fn = ALL_CHECKS[check_name]
        try:
            if check_name == "rate_limit":
                findings = fn(client, endpoints, burst_count=config.get("rate_limit_burst", 25))
            elif check_name == "jwt":
                findings = fn(client, endpoints, jwt_sample_token=config.get("jwt_sample_token"))
            elif check_name == "bfla":
                findings = fn(client, endpoints,
                              low_priv_auth_header=config.get("low_priv_auth_header"),
                              enable_verb_tampering=config.get("enable_verb_tampering", False))
            elif check_name == "graphql":
                findings = fn(client, endpoints, graphql_path=config.get("graphql_endpoint"))
            elif check_name == "business_logic":
                findings = fn(client, config.get("workflows", []))
            else:
                findings = fn(client, endpoints)
        except Exception as e:
            print(f"     check '{check_name}' raised an error: {e}")
            findings = []
        all_findings.extend(findings)

    print(f"\nTotal requests sent: {client.request_count}")
    print_console_summary(all_findings, base_url)
    write_html_report(all_findings, base_url, args.output, endpoints=endpoints)
    print(f"HTML report written to: {args.output}")


if __name__ == "__main__":
    main()
