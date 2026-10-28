"""
core.cve_lookup
----------------
Looks up known CVEs for a detected product/version against the NIST
National Vulnerability Database (NVD) REST API v2.0, and classifies each
result into a severity tier.

NVD's public rate limit is 5 requests / 30s without an API key, or
50 requests / 30s with a free key (https://nvd.nist.gov/developers/request-an-api-key).
Pass api_key= to raise your limit; the caller is still responsible for
pacing requests (both cli.py and gui/app.py add a small delay per lookup).
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def severity_from_score(score: Optional[float]) -> str:
    """Map a CVSS base score (0-10) to a severity tier."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Moderate"
    if score > 0.0:
        return "Low"
    return "None"


def _extract_score(metrics: dict):
    """Prefer CVSS v3.1, fall back to v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        block = metrics.get(key)
        if block:
            try:
                return float(block[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return None


def lookup_cves(
    product: str,
    version: Optional[str] = None,
    max_results: int = 5,
    api_key: Optional[str] = None,
    timeout: float = 10.0,
) -> List[Dict]:
    """Query NVD for CVEs matching `product` (+ `version` if given).

    Returns a list of plain dicts:
        {cve_id, description, cvss_score, severity, published}
    Returns [] on any network/parse error rather than raising, so a single
    failed lookup never aborts a whole scan.
    """
    if not product:
        return []

    keyword = f"{product} {version}".strip() if version else product
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(NVD_API, params=params, headers=headers, timeout=timeout)
        if resp.status_code == 403 or resp.status_code == 429:
            return []
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    findings: List[Dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        score = _extract_score(cve.get("metrics", {}))
        findings.append({
            "cve_id": cve_id,
            "description": description[:400],
            "cvss_score": score if score is not None else 0.0,
            "severity": severity_from_score(score),
            "published": (cve.get("published") or "")[:10],
        })

    # Highest severity first
    findings.sort(key=lambda f: f["cvss_score"], reverse=True)
    return findings


def polite_delay(seconds: float = 1.5) -> None:
    """Small pause between NVD lookups to stay under the public rate limit."""
    time.sleep(seconds)
