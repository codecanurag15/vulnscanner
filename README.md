<div align="center">

# 🛡️ vulnscanner

**Port scan → service fingerprint → CVE match → report, in one pass.**

A TCP port scanner that identifies live services, matches them against real
CVEs from the NIST National Vulnerability Database (NVD), and shows the
results as an animated terminal dashboard *or* a live-updating web console —
saving a styled HTML report at the end of every run.

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Interface](https://img.shields.io/badge/interface-CLI%20%7C%20GUI-8b5cf6)](#-quick-start)
[![Data source](https://img.shields.io/badge/CVE%20data-NVD-5eead4)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/license-unlicensed-lightgrey)](#-license)

</div>

> [!WARNING]
> Only scan systems you **own**, or have **explicit written authorization**
> to test. Scanning systems without permission is illegal in most
> jurisdictions (US CFAA, UK Computer Misuse Act, etc.) even when nothing
> is damaged. This tool detects and reports — it never exploits anything.

---

## Contents

- [Features](#-features)
- [Preview](#-preview)
- [Installation](#-installation)
- [Quick start](#-quick-start)
- [Configuration](#-configuration)
- [Reports](#-reports)
- [Project structure](#-project-structure)
- [How detection works](#-how-detection-works)
- [Limitations](#-limitations)
- [License](#-license)

## 🚀 Features

- 🔍 **Threaded TCP scan** of a curated ~90-port common-services list, or any custom range you give it
- 🧬 **Banner fingerprinting** — pulls product + version out of raw banners/HTTP headers (Apache, nginx, OpenSSH, MySQL/MariaDB, Redis, vsFTPd, Postfix, and more)
- 🗂️ **Real CVE matching** against the live NVD API — CVE ID, CVSS score, and a Critical / High / Moderate / Low severity tier
- 💻 **CLI** with an animated banner, live progress bars, spinners, and color-coded result tables, built on `rich`
- 🖥️ **GUI** — a dark, console-themed local web app with a 4-step scan tracker, a scrolling live log, and findings that populate in real time over Server-Sent Events
- 📄 **Self-contained HTML report** per scan, saved to `reports/`, viewable with nothing but a browser

## 👀 Preview

Sample CLI output:

```text
   ╔═══════════════════════════════════════════╗
   ║         V U L N S C A N N E R              ║
   ╚═══════════════════════════════════════════╝
   Advanced CVE-aware port scanner · for authorized security testing only

   ✔ Resolved example.com → 93.184.216.34

   Scanning ports   ████████████████████████░░░░  74/90   0:00:04
   Looking up CVEs  ████████████████████████████  3/3

   ╭──────────── Open Ports — example.com (93.184.216.34) ─────────────╮
   │ Port │ Service │ Product / Version │ Banner                       │
   │  22  │  SSH    │  OpenSSH 8.9      │  SSH-2.0-OpenSSH_8.9         │
   │  80  │  HTTP   │  Apache 2.4.49    │  Server: Apache/2.4.49       │
   ╰──────────────────────────────────────────────────────────────────╯

   ┏━━━━━━━━━━━━━━━━━━━━━━━ Vulnerabilities Found ━━━━━━━━━━━━━━━━━━━━━┓
   ┃ CVE-2021-41773 │ 80 │ 9.8 │ Critical │ Path traversal in Apache…  ┃
   ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

   ✔ Report saved: reports/example.com_20261028_120000.html
```

The GUI renders the same pipeline as a dark, glassy console in your
browser, with the progress bar, step tracker, and findings animating in
live as the scan runs.

> Drop a real screenshot or GIF of your terminal/browser run here once
> you've tried it — it'll sell the tool a lot better than ASCII art.

## 📦 Installation

Requires **Python 3.9+**.

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/vulnscanner.git
cd vulnscanner

# 2. (Recommended) create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

Verify it installed correctly:

```bash
python cli.py --help
```

## ⚡ Quick start

**CLI**

```bash
python cli.py example.com
python cli.py 192.168.1.10 --ports 1-1024 --threads 200
python cli.py example.com --api-key YOUR_NVD_KEY     # higher rate limit
```

| Flag | Default | Meaning |
|---|---|---|
| `--ports` | curated ~90-port list | e.g. `1-1024` or `22,80,443` |
| `--threads` | 150 | concurrent connection attempts |
| `--timeout` | 1.0 | per-port connect timeout (seconds) |
| `--api-key` | `$NVD_API_KEY` | NVD API key — see [Configuration](#-configuration) |
| `--max-cve` | 5 | CVEs pulled per detected service |
| `--out` | `reports/` | output directory for the HTML report |

**GUI**

```bash
python gui/app.py
```

Open **http://127.0.0.1:5050**, enter a target, optionally expand **Ports**
for a custom range or NVD key, and run the scan.

## ⚙️ Configuration

NVD allows 5 requests/30s without a key, or 50/30s with one. Past a
handful of fingerprinted services you'll want a free key:
https://nvd.nist.gov/developers/request-an-api-key

Use it either way:

```bash
export NVD_API_KEY=your-key-here      # picked up automatically
# or
python cli.py example.com --api-key your-key-here
```

## 📄 Reports

Every scan writes a self-contained HTML file to `reports/`, named
`<target>_<YYYYMMDD_HHMMSS>.html`, with severity counts, the full
open-port/service table, and a card per CVE finding linking to its NVD
page. Nothing else is required to view it — just open it in a browser.

## 🗂️ Project structure

```
vulnscanner/
├── core/
│   ├── scanner.py       # threaded TCP scan + banner grab + fingerprinting
│   ├── cve_lookup.py    # NVD API query + CVSS severity classification
│   └── report.py        # HTML report renderer
├── cli.py                # Rich-based terminal UI
├── gui/
│   ├── app.py             # Flask backend (Server-Sent Events for live progress)
│   ├── templates/index.html
│   └── static/{style.css, script.js}
├── reports/                # generated reports land here
└── requirements.txt
```

## 🔬 How detection works

1. Opens a plain TCP connection to each port in range and records which ones accept it.
2. Grabs whatever banner the service offers, or sends a minimal HTTP HEAD / newline probe to coax one out, then parses it for a product + version.
3. Searches NVD by that product/version keyword and returns any CVEs found, with CVSS score and severity.

It never attempts to exploit anything, brute-force credentials, or send
anything beyond a harmless connect/HEAD probe. CVE matches are keyword
matches against a banner string, not confirmed, version-exact proof —
treat them as leads to verify, the same way you'd treat Nmap's
vulnerability scripts or Nikto's output.

## ⚠️ Limitations

This is a lightweight banner-based scanner, not a replacement for a full
scanner like Nessus, OpenVAS, or Nuclei — no NSE-style scripted checks, no
authenticated scanning, no OS fingerprinting, and detection accuracy
depends entirely on what a service reveals in its banner. Closed or
firewalled ports, services that don't self-identify, and custom-built
software won't produce CVE matches even if they have known issues.

## 📜 License

No license file is included yet. MIT is a common, permissive choice for a
tool like this — add a `LICENSE` file with your preferred terms before you
publish the repo, so others know what they're allowed to do with it.
