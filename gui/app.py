#!/usr/bin/env python3
"""
vulnscanner GUI (Flask backend)
--------------------------------
Serves the web console and streams live scan progress to the browser over
Server-Sent Events (SSE) so the UI can animate port-by-port and CVE-by-CVE
as they're found, without any JS build step or websocket dependency.

Run from the project root:
    python gui/app.py
then open http://127.0.0.1:5050

⚠ Only scan systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Make `core` importable whether this is run as `python gui/app.py`
# or `python -m gui.app` from the project root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, Response, jsonify, request, send_from_directory, render_template

from core.cve_lookup import lookup_cves
from core.report import generate_html_report
from core.scanner import COMMON_PORTS, resolve_target, scan_port

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _safe_filename(target: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in target)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    target = (request.args.get("target") or "").strip()
    port_spec = (request.args.get("ports") or "").strip()
    api_key = (request.args.get("api_key") or os.environ.get("NVD_API_KEY") or None)

    def parse_ports(spec):
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

    def generate():
        if not target:
            yield sse("error", {"msg": "No target provided."})
            return

        start = time.time()
        try:
            ports = parse_ports(port_spec)
        except ValueError:
            yield sse("error", {"msg": f"Invalid port spec: {port_spec!r}"})
            return

        yield sse("log", {"msg": f"Resolving {target}..."})
        try:
            ip = resolve_target(target)
        except socket.gaierror:
            yield sse("error", {"msg": f"Could not resolve target: {target}"})
            return
        yield sse("resolved", {"ip": ip, "port_total": len(ports)})

        results = []
        done = 0
        with ThreadPoolExecutor(max_workers=150) as ex:
            futures = {ex.submit(scan_port, ip, p, 1.0): p for p in ports}
            for fut in as_completed(futures):
                done += 1
                try:
                    r = fut.result()
                except Exception:
                    r = None
                if r:
                    results.append(r)
                    yield sse("port_found", {
                        "port": r.port, "service": r.service,
                        "product": r.product, "version": r.version,
                        "banner": (r.banner or "")[:200],
                    })
                yield sse("progress", {"phase": "ports", "done": done, "total": len(ports)})

        results.sort(key=lambda r: r.port)
        yield sse("log", {"msg": f"{len(results)} open port(s) found. Looking up CVEs..."})

        fingerprinted = [r for r in results if r.product]
        all_findings = []
        cdone = 0
        for r in fingerprinted:
            findings = lookup_cves(r.product, r.version, max_results=5, api_key=api_key)
            for f in findings:
                f["port"] = r.port
                f["service"] = r.service
                all_findings.append(f)
                yield sse("cve_found", f)
            cdone += 1
            yield sse("progress", {"phase": "cve", "done": cdone, "total": max(len(fingerprinted), 1)})
            time.sleep(1.3 if not api_key else 0.3)

        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{_safe_filename(target)}_{ts}.html"
        report_path = os.path.join(REPORTS_DIR, filename)
        generate_html_report(target, ip, results, all_findings, report_path, duration_seconds=time.time() - start)

        yield sse("done", {
            "report_file": filename,
            "open_ports": len(results),
            "cve_count": len(all_findings),
            "duration": round(time.time() - start, 1),
        })

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.route("/reports/<path:filename>")
def get_report(filename):
    return send_from_directory(REPORTS_DIR, filename)


@app.route("/reports-list")
def reports_list():
    files = sorted(
        (f for f in os.listdir(REPORTS_DIR) if f.endswith(".html")),
        key=lambda f: os.path.getmtime(os.path.join(REPORTS_DIR, f)),
        reverse=True,
    )
    return jsonify(files[:20])


if __name__ == "__main__":
    print("vulnscanner GUI running at http://127.0.0.1:5050")
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)
