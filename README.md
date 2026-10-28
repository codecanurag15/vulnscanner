# vulnscanner

A TCP port scanner that fingerprints services from their banners, matches
them against known CVEs via the NIST National Vulnerability Database (NVD),
and produces a styled HTML report — available as both a terminal (CLI) tool
and a local web GUI.

**⚠ Only scan systems you own, or have explicit written authorization to
test.** Scanning systems without permission is illegal in most jurisdictions
(e.g. the US Computer Fraud and Abuse Act, UK Computer Misuse Act) even when
no damage is done. This tool only *detects and reports* — it does not
exploit anything.

## What it actually does (and doesn't)

- Opens a plain TCP connection to a list of ports and records which ones
  accept connections.
- Grabs whatever banner the service offers, or sends a minimal HTTP HEAD /
  newline probe to coax one out, and parses it for a product + version
  (Apache, nginx, OpenSSH, MySQL/MariaDB, Redis, vsFTPd, Postfix, etc.)
- Searches NVD by that product/version keyword and reports any CVEs it
  returns, with CVSS score and a severity tier (**Critical / High /
  Moderate / Low**).
- **Does not** attempt to exploit anything, brute-force credentials, or
  send anything beyond a harmless connect/HEAD probe.
- CVE matches are keyword matches against a banner string, not confirmed,
  version-exact vulnerability proof — treat them as leads to verify, the
  same way you'd treat Nmap's vulnerability scripts or Nikto's output.

## Setup

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

## CLI usage

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
| `--api-key` | `$NVD_API_KEY` | NVD API key — see below |
| `--max-cve` | 5 | CVEs pulled per detected service |
| `--out` | `reports/` | output directory for the HTML report |

## GUI usage

```bash
python gui/app.py
```

Then open **http://127.0.0.1:5050** — enter a target, optionally expand
**Ports** to set a custom range or NVD key, and run the scan. Progress
streams live (resolve → port scan → CVE match → report), and the finished
report is one click away.

## NVD API key (optional but recommended)

NVD allows 5 requests/30s without a key, or 50/30s with one. For anything
beyond a handful of fingerprinted services, get a free key:
https://nvd.nist.gov/developers/request-an-api-key — then either pass
`--api-key` / fill the GUI's key field, or set `NVD_API_KEY` as an
environment variable.

## Reports

Every scan writes a self-contained HTML file to `reports/`, named
`<target>_<YYYYMMDD_HHMMSS>.html`, with a summary of severity counts, the
full open-port/service table, and a card per CVE finding linking to its
NVD page. Nothing else is required to view it — just open it in a browser.

## Project layout

```
vulnscanner/
├── core/
│   ├── scanner.py      # threaded TCP scan + banner grab + fingerprinting
│   ├── cve_lookup.py    # NVD API query + CVSS severity classification
│   └── report.py        # HTML report renderer
├── cli.py                # Rich-based terminal UI
├── gui/
│   ├── app.py            # Flask backend (Server-Sent Events for live progress)
│   ├── templates/index.html
│   └── static/{style.css, script.js}
├── reports/               # generated reports land here
└── requirements.txt
```

## Limitations

This is a lightweight banner-based scanner, not a replacement for a full
scanner like Nessus, OpenVAS, or Nuclei — no NSE-style scripted checks, no
authenticated scanning, no OS fingerprinting, and detection accuracy
depends entirely on what a service reveals in its banner. Closed or
firewalled ports, services that don't self-identify, and custom-built
software won't produce CVE matches even if they have known issues.
# vulnscanner