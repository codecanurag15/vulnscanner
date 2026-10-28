#!/usr/bin/env python3
"""
vulnscanner CLI
----------------
Advanced-looking but dependency-light terminal vulnerability scanner.
Resolves a target, TCP-scans common ports, fingerprints services from
banners, looks up matching CVEs on NVD, prints colored results, and saves
a styled HTML report to reports/.

Usage:
    python cli.py example.com
    python cli.py 192.168.1.10 --ports 1-1000 --threads 200
    python cli.py example.com --api-key YOUR_NVD_KEY   # higher rate limit

⚠ Only scan systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from datetime import datetime

from rich.align import Align
from rich.box import DOUBLE, HEAVY_EDGE, ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from core.cve_lookup import lookup_cves, polite_delay
from core.report import generate_html_report
from core.scanner import COMMON_PORTS, resolve_target, scan_target

console = Console()

BANNER = r"""
__     ___   _ _     _   _     _    _   _ _____ ___ _____ _____
\ \   / / | | | |   | \ | |   / \  | | | |_   _|_ _| ____|_   _|
 \ \ / /| | | | |   |  \| |  / _ \ | |_| | | |  | ||  _|   | |
  \ V / | |_| | |___| |\  | / ___ \|  _  | | |  | || |___  | |
   \_/   \___/|_____|_| \_|/_/   \_\_| |_| |_| |___|_____| |_|
      S  C  A  N  N  E  R
"""

SEVERITY_STYLE = {
    "Critical": "bold white on red3",
    "High": "bold red",
    "Moderate": "bold yellow",
    "Low": "bold green",
    "Unknown": "dim",
    "None": "dim",
}


def print_banner() -> None:
    console.print()
    console.print(Panel(
        Align.center(Text(BANNER, style="bold cyan")),
        border_style="bright_magenta",
        box=DOUBLE,
        padding=(0, 2),
    ))
    console.print(Align.center(
        "[dim]Advanced CVE-aware port scanner  ·  [bold yellow]for authorized security testing only[/bold yellow][/dim]"
    ))
    console.print()


def parse_ports(spec: str | None):
    if not spec:
        return COMMON_PORTS
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscanner",
        description="Advanced CLI vulnerability scanner — port scan + CVE lookup + HTML report.",
    )
    p.add_argument("target", help="Domain, hostname, or IP address to scan")
    p.add_argument("--ports", help="Port spec, e.g. '1-1024' or '22,80,443'. Default: curated common-port list (~90 ports).")
    p.add_argument("--threads", type=int, default=150, help="Concurrent connection attempts (default 150)")
    p.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds (default 1.0)")
    p.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"), help="NVD API key for a higher rate limit")
    p.add_argument("--max-cve", type=int, default=5, help="Max CVEs to pull per detected service (default 5)")
    p.add_argument("--out", default="reports", help="Directory to save the HTML report into (default: reports/)")
    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    print_banner()
    start = time.time()

    try:
        with console.status(f"[bold cyan]Resolving {args.target}...", spinner="dots"):
            ip = resolve_target(args.target)
    except socket.gaierror:
        console.print(f"[bold red]✘ Could not resolve target:[/bold red] {args.target}")
        return 1
    console.print(f"[green]✔[/green] Resolved [bold]{args.target}[/bold] → [bold cyan]{ip}[/bold cyan]\n")

    ports = parse_ports(args.ports)

    # --- Phase 1: port scan -------------------------------------------------
    results = []
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=42, complete_style="bright_magenta", finished_style="green"),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports", total=len(ports))

        def cb(done, total, port):
            progress.update(task, completed=done)

        results = scan_target(ip, ports=ports, max_workers=args.threads, timeout=args.timeout, progress_cb=cb)

    console.print(f"\n[bold green]{len(results)}[/bold green] open port(s) found\n")

    # --- Phase 2: CVE lookup -------------------------------------------------
    fingerprinted = [r for r in results if r.product]
    all_findings = []
    if fingerprinted:
        with Progress(
            SpinnerColumn(style="magenta"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=42, complete_style="bright_cyan", finished_style="green"),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[magenta]Looking up CVEs on NVD", total=len(fingerprinted))
            for r in fingerprinted:
                findings = lookup_cves(r.product, r.version, max_results=args.max_cve, api_key=args.api_key)
                for f in findings:
                    f["port"] = r.port
                    f["service"] = r.service
                all_findings.extend(findings)
                progress.advance(task)
                polite_delay(1.3 if not args.api_key else 0.3)
    else:
        console.print("[dim]No fingerprintable services found — skipping CVE lookup.[/dim]\n")

    # --- Results: ports table -------------------------------------------------
    if results:
        table = Table(title=f"Open Ports — {args.target} ({ip})", box=ROUNDED, border_style="bright_blue", show_lines=False)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service")
        table.add_column("Product / Version")
        table.add_column("Banner", overflow="ellipsis", max_width=50, style="dim")
        for r in results:
            prod = f"{r.product or ''} {r.version or ''}".strip() or "—"
            table.add_row(str(r.port), r.service, prod, r.banner.replace("\n", " ").replace("\r", ""))
        console.print(table)
        console.print()

    # --- Results: CVE table -------------------------------------------------
    if all_findings:
        all_findings.sort(key=lambda f: -f["cvss_score"])
        cve_table = Table(title="Vulnerabilities Found", box=HEAVY_EDGE, border_style="red")
        cve_table.add_column("CVE ID", style="bold")
        cve_table.add_column("Port", justify="right")
        cve_table.add_column("Score", justify="right")
        cve_table.add_column("Severity")
        cve_table.add_column("Description", overflow="ellipsis", max_width=60)
        for f in all_findings:
            style = SEVERITY_STYLE.get(f["severity"], "white")
            cve_table.add_row(
                f["cve_id"],
                str(f.get("port", "")),
                f"{f['cvss_score']:.1f}",
                f"[{style}] {f['severity']} [/{style}]",
                f["description"],
            )
        console.print(cve_table)
    else:
        console.print("[green]✔ No known CVEs matched the fingerprinted services.[/green]")

    # --- Report ---------------------------------------------------------------
    os.makedirs(args.out, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() or c in "._-" else "_" for c in args.target)
    report_path = os.path.join(args.out, f"{safe_target}_{timestamp}.html")
    generate_html_report(args.target, ip, results, all_findings, report_path, duration_seconds=time.time() - start)

    console.print(f"\n[bold green]✔ Report saved:[/bold green] [underline]{report_path}[/underline]")
    console.print(f"[dim]Scan completed in {time.time() - start:.1f}s[/dim]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
