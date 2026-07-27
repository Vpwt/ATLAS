"""Business-logic / workflow-chaining checks (API6:2023-adjacent).

Config-driven: define a `workflows:` list of ordered steps (e.g. create an
order -> pay for it -> mark it fulfilled). This check replays each flow
twice:
  1. A baseline run, executing every step in order.
  2. Once per step marked `required: true`, with that step skipped entirely,
     to see whether the workflow can still be completed without it - a
     classic business-logic bypass (e.g. skipping a payment/approval step).

Values extracted from one step's response (via `extract`) are substituted
into later steps' `{placeholders}` in path/params/body.
"""
from scanner.models import Finding, Severity


def _substitute(value, variables: dict):
    if isinstance(value, str):
        for key, val in variables.items():
            value = value.replace("{" + key + "}", str(val))
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    return value


def _extract(response_json, extract_map: dict, variables: dict):
    for var_name, field_path in (extract_map or {}).items():
        value = response_json
        for part in field_path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
            if value is None:
                break
        if value is not None:
            variables[var_name] = value


def _run_steps(client, steps: list, variables: dict):
    """Executes `steps` in order. Returns (results, ok) where results is a
    list of (step_name, status_code) and ok is False if any step returned a
    non-2xx status or raised an error (i.e. the flow broke)."""
    results = []
    for step in steps:
        method = step.get("method", "GET").upper()
        path = _substitute(step["path"], variables)
        body = _substitute(step.get("body"), variables)
        params = _substitute(step.get("params", {}), variables)

        try:
            resp = client.request(method, path, params=params if method == "GET" else None,
                                   json_body=body, auth_override="keep")
        except Exception:
            results.append((step["name"], None))
            return results, False

        results.append((step["name"], resp.status_code))
        if resp.status_code >= 300:
            return results, False

        if step.get("extract"):
            try:
                _extract(resp.json(), step["extract"], variables)
            except ValueError:
                pass

    return results, True


def run(client, workflows: list) -> list[Finding]:
    findings = []
    if not workflows:
        return findings

    for workflow in workflows:
        name = workflow.get("name", "workflow")
        steps = workflow.get("steps", [])
        if not steps:
            continue

        baseline_variables = {}
        baseline_results, baseline_ok = _run_steps(client, steps, baseline_variables)

        if not baseline_ok:
            findings.append(Finding(
                check="business_logic", severity=Severity.INFO,
                title=f"Workflow '{name}' did not complete - skipping bypass tests",
                endpoint=f"workflow: {name}",
                detail=(f"The baseline run of workflow '{name}' did not complete successfully "
                        f"(step results: {baseline_results}), so step-skipping bypass tests were "
                        "skipped for it. Double-check the workflow's paths/bodies/auth in "
                        "config.yaml."),
            ))
            continue

        for skip_step in (s for s in steps if s.get("required")):
            remaining_steps = [s for s in steps if s is not skip_step]
            variables = dict(baseline_variables)  # fall back on baseline-extracted values
            results, ok = _run_steps(client, remaining_steps, variables)

            if ok:
                findings.append(Finding(
                    check="business_logic", severity=Severity.CRITICAL,
                    title=f"Possible business logic bypass: step '{skip_step['name']}' can be skipped",
                    endpoint=f"workflow: {name}",
                    detail=(f"Workflow '{name}' completed successfully even when the required "
                            f"step '{skip_step['name']}' was skipped entirely. If this step "
                            "represents something like payment, approval, or verification, an "
                            "attacker may be able to bypass it and still reach the final state."),
                    evidence=f"results without '{skip_step['name']}': {results}",
                    owasp_ref="API6:2023 Unrestricted Access to Sensitive Business Flows",
                ))

    return findings
