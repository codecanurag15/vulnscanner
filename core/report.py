"""
core.report
-----------
Builds a single self-contained HTML report (no external files needed besides
two Google Fonts loaded over the network when the report is viewed) for one
scan run, and saves it into the reports/ directory.
"""

from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Dict, List

from .scanner import PortResult

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3, "Unknown": 4, "None": 5}

SEVERITY_HEX = {
    "Critical": "#ff5c5c",
    "High": "#ff9f43",
    "Moderate": "#ffd93d",
    "Low": "#4ade80",
    "Unknown": "#8891a7",
    "None": "#8891a7",
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _severity_counts(findings: List[Dict]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Moderate": 0, "Low": 0, "Unknown": 0}
    for f in findings:
        sev = f.get("severity", "Unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _port_rows_html(results: List[PortResult]) -> str:
    if not results:
        return '<p class="empty">No open ports were detected on the scanned range.</p>'
    rows = []
    for r in results:
        product = f"{r.product or ''} {r.version or ''}".strip() or "—"
        banner = _esc(r.banner.replace("\n", " ").replace("\r", " "))[:140]
        rows.append(f"""
        <tr>
          <td class="mono">{r.port}</td>
          <td>{_esc(r.service)}</td>
          <td class="mono">{_esc(product)}</td>
          <td class="mono dim">{banner}</td>
        </tr>""")
    return f"""
    <table class="port-table">
      <thead>
        <tr><th>Port</th><th>Service</th><th>Product / Version</th><th>Banner</th></tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>"""


def _finding_strip_html(f: Dict) -> str:
    sev = f.get("severity", "Unknown")
    color = SEVERITY_HEX.get(sev, "#8891a7")
    cve_id = _esc(f.get("cve_id", "UNKNOWN"))
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else "#"
    score = f.get("cvss_score", 0.0) or 0.0
    port = f.get("port", "")
    service = f.get("service", "")
    desc = _esc(f.get("description", "") or "No description available.")
    published = _esc(f.get("published", "") or "—")
    return f"""
    <div class="finding" style="border-left-color:{color}">
      <div class="finding-head">
        <a class="cve-id" href="{nvd_url}" target="_blank" rel="noopener">{cve_id}</a>
        <span class="pill" style="background:{color}22;color:{color};border-color:{color}55">{_esc(sev)}</span>
        <span class="score mono">{score:.1f}</span>
        <span class="finding-meta mono">
          <span class="chip">port {_esc(port)}</span><span class="chip">{_esc(service)}</span><span class="chip">published {published}</span>
        </span>
      </div>
      <p class="finding-desc">{desc}</p>
    </div>"""


def generate_html_report(
    target: str,
    ip: str,
    port_results: List[PortResult],
    findings: List[Dict],
    output_path: str,
    duration_seconds: float | None = None,
) -> str:
    """Render the report and write it to output_path. Returns output_path."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    counts = _severity_counts(findings)
    sorted_findings = sorted(
        findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "Unknown"), 9), -f.get("cvss_score", 0))
    )
    findings_html = "".join(_finding_strip_html(f) for f in sorted_findings) or (
        '<p class="empty">No known CVEs matched the fingerprinted services.</p>'
    )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = f"{duration_seconds:.1f}s" if duration_seconds else "—"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scan report · {_esc(target)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0b0e14;
    --panel: #12161f;
    --panel-2: #161b26;
    --border: #262c3a;
    --text: #dbe1ee;
    --dim: #8891a7;
    --accent: #5eead4;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: radial-gradient(ellipse at top, #10141e 0%, #0b0e14 60%);
    color: var(--text);
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    line-height: 1.55;
  }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 48px 24px 80px; }}
  h1, h2 {{ font-family: 'Space Grotesk', sans-serif; font-weight: 600; margin: 0; }}
  header.report-head {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
  .kicker {{ color: var(--accent); font-size: 13px; margin: 0 0 8px; font-family: 'Space Grotesk', sans-serif; }}
  h1 {{ font-size: 28px; color: #fff; }}
  .target-ip {{ color: var(--dim); font-size: 14px; margin-top: 6px; }}
  .meta-row {{ display: flex; gap: 24px; margin-top: 18px; flex-wrap: wrap; font-size: 13px; color: var(--dim); }}
  .meta-row b {{ color: var(--text); font-weight: 500; }}

  .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 40px; }}
  .tile {{ background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 16px 14px; }}
  .tile .n {{ font-family: 'Space Grotesk', sans-serif; font-size: 26px; font-weight: 700; color: #fff; }}
  .tile .label {{ font-size: 12px; color: var(--dim); margin-top: 4px; }}

  section {{ margin-bottom: 40px; }}
  h2 {{ font-size: 18px; color: #fff; margin-bottom: 14px; }}
  h2 .count {{ color: var(--dim); font-weight: 400; font-size: 14px; }}

  table.port-table {{ width: 100%; border-collapse: collapse; font-size: 13px; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
  table.port-table th {{ text-align: left; font-family: 'Space Grotesk', sans-serif; font-weight: 600; font-size: 12px; color: var(--dim); padding: 10px 14px; border-bottom: 1px solid var(--border); background: var(--panel-2); }}
  table.port-table td {{ padding: 9px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  table.port-table tr:last-child td {{ border-bottom: none; }}
  .mono {{ font-family: 'JetBrains Mono', monospace; }}
  .dim {{ color: var(--dim); }}

  .finding {{ background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--dim); border-radius: 4px; padding: 14px 16px; margin-bottom: 10px; }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .cve-id {{ font-family: 'Space Grotesk', sans-serif; font-weight: 600; color: #fff; text-decoration: none; font-size: 14px; }}
  .cve-id:hover {{ color: var(--accent); }}
  .pill {{ font-size: 11px; padding: 3px 9px; border-radius: 100px; border: 1px solid; font-family: 'Space Grotesk', sans-serif; font-weight: 600; }}
  .score {{ font-size: 12px; color: var(--text); }}
  .finding-meta {{ margin-left: auto; display: flex; gap: 8px; }}
  .chip {{ font-size: 11px; color: var(--dim); background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; }}
  .finding-desc {{ font-size: 13px; color: var(--text); margin: 10px 0 0; max-width: 78ch; }}

  .empty {{ color: var(--dim); font-size: 14px; }}
  footer {{ border-top: 1px solid var(--border); padding-top: 20px; margin-top: 48px; font-size: 12px; color: var(--dim); }}
  footer .warn {{ color: #ff9f43; }}

  @media (max-width: 640px) {{
    .summary {{ grid-template-columns: repeat(2, 1fr); }}
    table.port-table {{ display: block; overflow-x: auto; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header class="report-head">
    <p class="kicker">Vulnerability scan report</p>
    <h1>{_esc(target)}</h1>
    <div class="target-ip">resolved to {_esc(ip)}</div>
    <div class="meta-row">
      <div>Generated <b>{generated}</b></div>
      <div>Duration <b>{duration}</b></div>
      <div>Open ports <b>{len(port_results)}</b></div>
      <div>CVEs matched <b>{len(findings)}</b></div>
    </div>
  </header>

  <div class="summary">
    <div class="tile"><div class="n" style="color:{SEVERITY_HEX['Critical']}">{counts['Critical']}</div><div class="label">Critical</div></div>
    <div class="tile"><div class="n" style="color:{SEVERITY_HEX['High']}">{counts['High']}</div><div class="label">High</div></div>
    <div class="tile"><div class="n" style="color:{SEVERITY_HEX['Moderate']}">{counts['Moderate']}</div><div class="label">Moderate</div></div>
    <div class="tile"><div class="n" style="color:{SEVERITY_HEX['Low']}">{counts['Low']}</div><div class="label">Low</div></div>
    <div class="tile"><div class="n">{len(port_results)}</div><div class="label">Open ports</div></div>
  </div>

  <section>
    <h2>Open ports &amp; fingerprinted services</h2>
    {_port_rows_html(port_results)}
  </section>

  <section>
    <h2>Vulnerabilities <span class="count">({len(findings)} matched via NVD)</span></h2>
    {findings_html}
  </section>

  <footer>
    <p>Generated by <b>vulnscanner</b>. CVE data sourced from the NIST National Vulnerability Database (NVD) by keyword match on fingerprinted service/version banners — treat matches as leads to verify, not confirmed exploitability.</p>
    <p class="warn">Only scan systems you own or have explicit written authorization to test.</p>
  </footer>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return output_path
