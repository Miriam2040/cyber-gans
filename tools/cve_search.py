"""
NVD CVE search. Each query is cached separately so repeated runs don't hit the API.
Falls back to the local cves.json bank when NVD returns empty or times out.
Used as a tool by the attacker agent.
"""

import json
import time
import urllib.request
import urllib.parse
from pathlib import Path

CACHE_DIR  = Path("data/cve_cache")
LOCAL_BANK = Path("data/cves.json")
NVD        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CVE_YEAR = 2025  # exclude future/unverifiable CVEs (2026+)


def _is_verifiable(cve: dict) -> bool:
    """Reject CVEs that can't be independently verified:
    - Future years (2026+) — reserved IDs with no published details
    - Descriptions under 60 chars — too vague to verify mechanism
    """
    cve_id = cve.get("id", "")
    try:
        year = int(cve_id[4:8])
        if year > MAX_CVE_YEAR:
            return False
    except (ValueError, IndexError):
        return False
    desc = cve.get("description", "")
    return len(desc) >= 60


def _local_search(query: str, max_results: int = 10) -> list[dict]:
    """Keyword search over the local cves.json bank."""
    if not LOCAL_BANK.exists():
        return []
    bank = json.loads(LOCAL_BANK.read_text())
    terms = query.lower().split()
    scored = []
    for cve in bank:
        text = (cve.get("id", "") + " " + cve.get("description", "")).lower()
        hits = sum(1 for t in terms if t in text)
        if hits > 0:
            scored.append((hits, cve))
    scored.sort(key=lambda x: -x[0])
    return [c for _, c in scored[:max_results] if _is_verifiable(c)]


def search(query: str, max_results: int = 10) -> list[dict]:
    """Search NVD for CVEs matching query. Returns list of {id, description, severity}.
    Falls back to local bank when NVD is empty or unavailable."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key  = urllib.parse.quote(query.lower().strip(), safe="")[:80]
    path = CACHE_DIR / f"{key}.json"

    if path.exists():
        cached = json.loads(path.read_text())
        # If cached result is empty, try local bank as supplement
        if not cached:
            local = _local_search(query, max_results)
            if local:
                return local
        return cached

    time.sleep(0.6)  # NVD rate limit: 5 req / 30s unauthenticated
    url = f"{NVD}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage={max_results}"
    req = urllib.request.Request(url, headers={"User-Agent": "cyber-gans-research"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = json.loads(r.read())
    except Exception as e:
        print(f"  ⚠️  NVD request failed ({e}) — falling back to local bank")
        local = _local_search(query, max_results)
        if local:
            print(f"  📚 Local bank returned {len(local)} CVE(s)")
            path.write_text(json.dumps(local, indent=2))
            return local
        path.write_text("[]")
        return []

    results = []
    for item in raw.get("vulnerabilities", []):
        cve  = item["cve"]
        desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        if len(desc) < 60 or "REJECT" in desc:
            continue
        entry = {
            "id":          cve["id"],
            "description": desc[:400],
            "severity":    (
                cve.get("metrics", {})
                   .get("cvssMetricV31", [{}])[0]
                   .get("cvssData", {})
                   .get("baseSeverity", "UNKNOWN")
            ),
        }
        if not _is_verifiable(entry):
            continue
        results.append(entry)

    # If NVD returned nothing, supplement with local bank
    if not results:
        local = _local_search(query, max_results)
        if local:
            print(f"  📚 NVD empty — local bank returned {len(local)} CVE(s)")
            path.write_text(json.dumps(local, indent=2))
            return local

    path.write_text(json.dumps(results, indent=2))
    return results
