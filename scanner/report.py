"""Generates console summary and a self-contained HTML report from findings."""
from datetime import datetime
from scanner.models import Finding, severity_rank

SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#1d4ed8",
    "INFO": "#374151",
}


def print_console_summary(findings: list[Finding], base_url: str):
    findings_sorted = sorted(findings, key=lambda f: severity_rank(f.severity))
    counts = {}
    for f in findings_sorted:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    print("\n" + "=" * 60)
    print(f" API Security Scan Report - {base_url}")
    print(f" Generated: {datetime.now().isoformat(timespec='seconds')}")
    print("=" * 60)
    print(f" Total findings: {len(findings_sorted)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            print(f"   {sev:<9}: {counts[sev]}")
    print("-" * 60)

    for f in findings_sorted:
        print(f"[{f.severity.value}] {f.title}")
        print(f"   Endpoint: {f.endpoint}")
        print(f"   Check:    {f.check}")
        print(f"   CVSS:     {f.cvss_score}")
        if f.owasp_ref:
            print(f"   OWASP:    {f.owasp_ref}")
        print(f"   Detail:   {f.detail}")
        if f.evidence:
            print(f"   Evidence: {f.evidence}")
        if f.curl_repro:
            print(f"   PoC:      {f.curl_repro}")
        print()


def write_html_report(findings: list[Finding], base_url: str, output_path: str, endpoints: list = None):
    findings_sorted = sorted(findings, key=lambda f: severity_rank(f.severity))
    counts = {}
    for f in findings_sorted:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    rows = []
    for f in findings_sorted:
        color = SEVERITY_COLORS.get(f.severity.value, "#374151")
        poc_cell = f'<code>{_esc(f.curl_repro)}</code>' if f.curl_repro else ""
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity.value}</span></td>
          <td>{f.cvss_score}</td>
          <td>{_esc(f.title)}</td>
          <td><code>{_esc(f.endpoint)}</code></td>
          <td>{_esc(f.check)}</td>
          <td>{_esc(f.owasp_ref)}</td>
          <td>{_esc(f.detail)}</td>
          <td><code>{_esc(f.evidence)}</code></td>
          <td>{poc_cell}</td>
        </tr>""")

    summary_badges = "".join(
        f'<span class="badge" style="background:{SEVERITY_COLORS.get(sev, "#374151")}">{sev}: {count}</span>'
        for sev, count in counts.items()
    )

    inventory_rows = []
    for ep in endpoints or []:
        flags = []
        if ep.auth_required:
            flags.append("auth")
        if ep.admin_only:
            flags.append("admin_only")
        inventory_rows.append(f"""
        <tr>
          <td>{_esc(ep.method)}</td>
          <td><code>{_esc(ep.path)}</code></td>
          <td>{_esc(", ".join(flags) or "public")}</td>
          <td>{_esc(ep.description)}</td>
        </tr>""")

        inventory_html = ""
        if inventory_rows:
                graph_html = _build_attack_surface_graph(endpoints or [])
                inventory_html = f"""
    <h2>Attack surface (endpoints tested)</h2>
    {graph_html}
    <table><thead><tr><th>Method</th><th>Path</th><th>Flags</th><th>Description</th></tr></thead>
    <tbody>{"".join(inventory_rows)}</tbody></table>
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Security Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background: #0f1115; color: #e5e7eb; margin: 0; padding: 2rem; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  .meta {{ color: #9ca3af; font-size: 0.85rem; margin-bottom: 1rem; }}
  .summary {{ margin-bottom: 1.5rem; }}
  .badge {{ display: inline-block; color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.4rem; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.85rem; margin-bottom: 1rem; }}
  th, td {{ text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid #262b33; vertical-align: top; }}
  th {{ background: #1a1e26; position: sticky; top: 0; }}
  code {{ background: #1a1e26; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.8rem; word-break: break-all; }}
  .no-findings {{ color: #9ca3af; padding: 2rem; text-align: center; }}
    .graph-wrap {{ background: #121722; border: 1px solid #262b33; border-radius: 8px; padding: 0.75rem; margin-bottom: 1rem; }}
    .graph-note {{ color: #9ca3af; font-size: 0.8rem; margin: 0.25rem 0 0; }}
    details summary {{ cursor: pointer; color: #cbd5e1; font-size: 0.85rem; }}
</style>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script>if(window.mermaid){{mermaid.initialize({{startOnLoad:true, theme:'dark'}});}}</script>
</head>
<body>
  <h1>API Security Scan Report</h1>
  <div class="meta">Target: {_esc(base_url)} &middot; Generated: {datetime.now().isoformat(timespec='seconds')}</div>
  <div class="summary">{summary_badges if counts else '<span class="badge" style="background:#166534">No findings</span>'}</div>
  {"<table><thead><tr><th>Severity</th><th>CVSS</th><th>Title</th><th>Endpoint</th><th>Check</th><th>OWASP Ref</th><th>Detail</th><th>Evidence</th><th>PoC (curl)</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>" if rows else '<div class="no-findings">No issues found by the checks that ran.</div>'}
  {inventory_html}
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)


def _esc(text) -> str:
    if text is None:
        return ""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _safe_node_id(value: str) -> str:
    chars = []
    for ch in value:
        if ch.isalnum():
            chars.append(ch)
        else:
            chars.append("_")
    return "".join(chars)[:80] or "node"


def _build_attack_surface_graph(endpoints: list) -> str:
    if not endpoints:
        return ""

    lines = ["flowchart LR", "  root[\"API\"]"]
    method_nodes = {}

    for ep in endpoints:
        method = (ep.method or "GET").upper()
        method_id = f"m_{_safe_node_id(method)}"
        if method_id not in method_nodes:
            lines.append(f"  {method_id}[\"{method}\"]")
            lines.append(f"  root --> {method_id}")
            method_nodes[method_id] = True

        path_label = _esc(ep.path)
        endpoint_id = f"e_{_safe_node_id(method + '_' + ep.path)}"
        lines.append(f"  {endpoint_id}[\"{path_label}\"]")
        lines.append(f"  {method_id} --> {endpoint_id}")

    mermaid_text = "\n".join(lines)
    return (
        '<div class="graph-wrap">'
        '<div class="mermaid">' + mermaid_text + '</div>'
        '<p class="graph-note">Method-to-endpoint map for quick visual triage.</p>'
        '<details><summary>Show Mermaid source</summary>'
        '<pre><code>' + _esc(mermaid_text) + '</code></pre></details>'
        '</div>'
    )
