# Data Model v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the flat-CSV pipeline into a normalized relational dataset with 6 tables (vulnerabilities, cvss, commits, files, affected_packages, references) plus a flat convenience view, extracting all available fields from OSV/NVD/GitHub sources.

**Architecture:** New `scripts/build_tables.py` reads raw OSV JSON + NVD JSON to produce vulnerability-side tables. Extended `scripts/github_data.py` produces commit + file tables. New curate step joins them into the flat view. All tables output to `dataset/v2/`.

**Tech Stack:** Python 3.12, pandas, cvss (PyPI), json, concurrent.futures

**Spec:** `docs/superpowers/specs/2026-03-24-data-model-v2-design.md`

---

### Task 1: Add `cvss` library and create CVSS vector parser utility

A shared utility to parse CVSS vector strings into individual components. Used by both OSV and NVD table builders.

**Files:**
- Create: `scripts/lib/cvss_parser.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Add `cvss` to requirements.txt**

Add `cvss` to the end of `requirements.txt`.

Run: `pip install cvss`

- [ ] **Step 2: Write the CVSS parser module**

```python
"""Parse CVSS vector strings into component dicts."""
import json
import logging
from cvss import CVSS2, CVSS3

log = logging.getLogger(__name__)

# Maps from CVSS library short codes to spec-required full names
V3_AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
V3_AC_MAP = {"L": "LOW", "H": "HIGH"}
V3_PR_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}
V3_UI_MAP = {"N": "NONE", "R": "REQUIRED"}
V3_S_MAP = {"U": "UNCHANGED", "C": "CHANGED"}
V3_CIA_MAP = {"N": "NONE", "L": "LOW", "H": "HIGH"}

V2_AV_MAP = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL"}
V2_AC_MAP = {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}
V2_AU_MAP = {"N": "NONE", "S": "SINGLE", "M": "MULTIPLE"}
V2_CIA_MAP = {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}


def parse_cvss_vector(vector_string):
    """Parse a CVSS vector string into a dict of components.

    Returns dict with keys matching cvss.csv schema. Returns None if parsing fails.
    The cvss library's .metrics property returns a flat dict of short codes
    (e.g., {"AV": "N", "AC": "L"}). We map these to full names per the spec.
    """
    if not vector_string or not isinstance(vector_string, str):
        return None

    try:
        if vector_string.startswith("CVSS:3"):
            c = CVSS3(vector_string)
            version = "3.1" if "CVSS:3.1" in vector_string else "3.0"
            scores = c.scores()
            severities = c.severities()
            m = c.metrics  # flat dict: {"AV": "N", "AC": "L", ...}
            return {
                "cvss_version": version,
                "vector_string": vector_string,
                "base_score": scores[0],
                "base_severity": severities[0].upper() if severities[0] else None,
                "attack_vector": V3_AV_MAP.get(m.get("AV")),
                "attack_complexity": V3_AC_MAP.get(m.get("AC")),
                "privileges_required": V3_PR_MAP.get(m.get("PR")),
                "user_interaction": V3_UI_MAP.get(m.get("UI")),
                "scope": V3_S_MAP.get(m.get("S")),
                "authentication": None,
                "confidentiality_impact": V3_CIA_MAP.get(m.get("C")),
                "integrity_impact": V3_CIA_MAP.get(m.get("I")),
                "availability_impact": V3_CIA_MAP.get(m.get("A")),
                "exploitability_score": None,
                "impact_score": None,
            }
        elif vector_string.startswith("AV:") or vector_string.startswith("(AV:"):
            clean = vector_string.strip("()")
            c = CVSS2(clean)
            scores = c.scores()
            m = c.metrics  # flat dict: {"AV": "N", "AC": "L", "Au": "N", ...}
            return {
                "cvss_version": "2.0",
                "vector_string": vector_string,
                "base_score": scores[0],
                "base_severity": c.severities()[0].upper() if c.severities()[0] else None,
                "attack_vector": V2_AV_MAP.get(m.get("AV")),
                "attack_complexity": V2_AC_MAP.get(m.get("AC")),
                "privileges_required": None,
                "user_interaction": None,
                "scope": None,
                "authentication": V2_AU_MAP.get(m.get("Au")),
                "confidentiality_impact": V2_CIA_MAP.get(m.get("C")),
                "integrity_impact": V2_CIA_MAP.get(m.get("I")),
                "availability_impact": V2_CIA_MAP.get(m.get("A")),
                "exploitability_score": None,
                "impact_score": None,
            }
    except Exception as e:
        log.warning("Failed to parse CVSS vector '%s': %s", vector_string, e)
        return None

    return None
```

**Important:** After installing the `cvss` library, verify the `.metrics` API actually returns a flat dict. Run:
```bash
python3 -c "from cvss import CVSS3; c = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'); print(type(c.metrics), c.metrics)"
```
If the API differs, adjust the accessor code accordingly. The mapping dicts and return shape are fixed.

- [ ] **Step 3: Verify it works**

Run:
```bash
python3 -c "
import sys; sys.path.insert(0, 'scripts')
from lib.cvss_parser import parse_cvss_vector
v3 = parse_cvss_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
print('v3 score:', v3['base_score'], 'severity:', v3['base_severity'], 'AV:', v3['attack_vector'])
v2 = parse_cvss_vector('AV:N/AC:L/Au:N/C:P/I:P/A:P')
print('v2 score:', v2['base_score'], 'auth:', v2['authentication'])
print('OK')
"
```
Expected: v3 AV should be `NETWORK` (not `N`). Scores printed, `OK` at end.

- [ ] **Step 4: Commit**

```bash
git add scripts/lib/cvss_parser.py requirements.txt
git commit -m "feat: add CVSS vector parser utility"
```

---

### Task 2: Build `scripts/build_tables.py` — vulnerabilities and cvss tables

Reads raw OSV JSON files and NVD JSON, deduplicates by alias, outputs `dataset/v2/vulnerabilities.csv` and `dataset/v2/cvss.csv`.

**Files:**
- Create: `scripts/build_tables.py`

- [ ] **Step 1: Write the vulnerability/CVSS table builder**

This is the largest new file. It needs to:

1. Walk `data/osv/raw/{ecosystem}/*.json` and load each OSV entry
2. Load `data/nvd/raw/nvd_cves.json`
3. Filter out OSV `withdrawn` entries and NVD `Rejected` entries
4. Build a union-find over aliases to deduplicate
5. For each unique vuln, pick canonical ID (CVE when available)
6. Output `vulnerabilities.csv` and `cvss.csv`

```python
#!/usr/bin/env python3
"""Build normalized vulnerability tables from raw OSV + NVD data.

Outputs:
    dataset/v2/vulnerabilities.csv
    dataset/v2/cvss.csv
    dataset/v2/affected_packages.csv
    dataset/v2/references.csv
"""
import csv
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.cvss_parser import parse_cvss_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "dataset" / "v2"
CSV_OPTS = dict(quoting=csv.QUOTE_NONNUMERIC, escapechar="\\", doublequote=False, index=False)


# ---------- Union-Find for alias deduplication ----------

class UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, x):
        if x not in self.parent:
            self.parent[x] = x
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Prefer CVE IDs as root
            if rb.startswith("CVE-"):
                ra, rb = rb, ra
            self.parent[rb] = ra

    def groups(self):
        groups = defaultdict(set)
        for x in self.parent:
            groups[self.find(x)].add(x)
        return groups


# ---------- OSV loading ----------

def load_osv_entries(raw_dir):
    """Load all OSV JSON files, skip withdrawn entries."""
    entries = []
    raw_path = Path(raw_dir)
    for eco_dir in sorted(raw_path.iterdir()):
        if not eco_dir.is_dir():
            continue
        ecosystem = eco_dir.name
        for fpath in eco_dir.glob("*.json"):
            try:
                with open(fpath) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if "withdrawn" in data:
                continue
            data["_ecosystem"] = ecosystem
            entries.append(data)
    log.info("Loaded %d OSV entries (after filtering withdrawn)", len(entries))
    return entries


# ---------- NVD loading ----------

def load_nvd_entries(json_path):
    """Load NVD CVEs, skip Rejected entries."""
    with open(json_path) as f:
        raw = json.load(f)
    entries = []
    for item in raw:
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
        entries.append(cve)
    log.info("Loaded %d NVD entries (after filtering Rejected)", len(entries))
    return entries


# ---------- Build vulnerabilities + cvss ----------

def extract_osv_cvss(data):
    """Extract CVSS records from an OSV entry."""
    records = []
    for sev in data.get("severity", []):
        score_str = sev.get("score", "")
        parsed = parse_cvss_vector(score_str)
        if parsed:
            parsed["source"] = "osv"
            records.append(parsed)
    return records


def extract_nvd_cvss(cve):
    """Extract CVSS records from an NVD entry."""
    records = []
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in cve.get("metrics", {}).get(metric_key, []):
            cvss_data = metric.get("cvssData", {})
            version = cvss_data.get("version", "")
            if version.startswith("3"):
                rec = {
                    "cvss_version": version,
                    "vector_string": cvss_data.get("vectorString"),
                    "base_score": cvss_data.get("baseScore"),
                    "base_severity": cvss_data.get("baseSeverity"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity"),
                    "privileges_required": cvss_data.get("privilegesRequired"),
                    "user_interaction": cvss_data.get("userInteraction"),
                    "scope": cvss_data.get("scope"),
                    "authentication": None,
                    "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                    "integrity_impact": cvss_data.get("integrityImpact"),
                    "availability_impact": cvss_data.get("availabilityImpact"),
                    "exploitability_score": metric.get("exploitabilityScore"),
                    "impact_score": metric.get("impactScore"),
                    "source": metric.get("source", "nvd"),
                }
            else:
                rec = {
                    "cvss_version": "2.0",
                    "vector_string": cvss_data.get("vectorString"),
                    "base_score": cvss_data.get("baseScore"),
                    "base_severity": metric.get("baseSeverity"),
                    "attack_vector": cvss_data.get("accessVector"),
                    "attack_complexity": cvss_data.get("accessComplexity"),
                    "privileges_required": None,
                    "user_interaction": None,
                    "scope": None,
                    "authentication": cvss_data.get("authentication"),
                    "confidentiality_impact": cvss_data.get("confidentialityImpact"),
                    "integrity_impact": cvss_data.get("integrityImpact"),
                    "availability_impact": cvss_data.get("availabilityImpact"),
                    "exploitability_score": metric.get("exploitabilityScore"),
                    "impact_score": metric.get("impactScore"),
                    "source": metric.get("source", "nvd"),
                }
            records.append(rec)
    return records


def pick_best_cvss(cvss_records):
    """Pick the best CVSS record (v3.1 > v3.0 > v2.0) for the vuln summary row."""
    priority = {"3.1": 0, "3.0": 1, "2.0": 2}
    best = None
    for rec in cvss_records:
        if best is None or priority.get(rec["cvss_version"], 9) < priority.get(best["cvss_version"], 9):
            best = rec
    return best


def get_en_description(cve):
    """Get English description from NVD entry."""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value")
    return None


def get_nvd_cwes(cve):
    """Extract CWE IDs from NVD entry."""
    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.add(val)
    return cwes


def build_vuln_and_cvss_tables(osv_entries, nvd_entries):
    """Build vulnerabilities.csv and cvss.csv using union-find dedup."""

    # Step 1: Build union-find over all IDs
    uf = UnionFind()
    osv_by_id = {}
    for entry in osv_entries:
        entry_id = entry.get("id", "")
        aliases = entry.get("aliases", [])
        all_ids = [entry_id] + aliases
        for i in range(1, len(all_ids)):
            uf.union(all_ids[0], all_ids[i])
        osv_by_id[entry_id] = entry

    nvd_by_id = {}
    for cve in nvd_entries:
        cve_id = cve.get("id", "")
        uf.find(cve_id)  # register in union-find
        nvd_by_id[cve_id] = cve

    groups = uf.groups()
    log.info("Deduplication: %d unique vulnerability groups from %d OSV + %d NVD entries",
             len(groups), len(osv_entries), len(nvd_entries))

    vuln_rows = []
    cvss_rows = []

    for canonical_id, members in groups.items():
        # Gather all OSV and NVD entries in this group
        osv_group = [osv_by_id[m] for m in members if m in osv_by_id]
        nvd_group = [nvd_by_id[m] for m in members if m in nvd_by_id]

        # Determine canonical vuln_id (prefer CVE)
        vuln_id = canonical_id
        for m in sorted(members):
            if m.startswith("CVE-"):
                vuln_id = m
                break

        # Collect aliases
        aliases = sorted(members - {vuln_id})

        # Source datasets
        sources = []
        if osv_group:
            sources.append("osv")
        if nvd_group:
            sources.append("nvd")

        # Merge fields
        summary = None
        details = None
        cwe_ids = set()
        published_date = None
        modified_date = None

        # OSV data (prefer for narrative)
        for osv in osv_group:
            if not summary:
                summary = osv.get("summary")
            if not details:
                details = osv.get("details")
            published_date = published_date or osv.get("published")
            modified_date = modified_date or osv.get("modified")
            # CWEs from OSV
            db_spec = osv.get("database_specific", {})
            if "cwe_ids" in db_spec:
                cwe_ids.update(db_spec["cwe_ids"])
            for aff in osv.get("affected", []):
                aff_db = aff.get("database_specific", {})
                for cwe in aff_db.get("cwes", []):
                    cwe_ids.add(cwe.get("cweId", cwe.get("id", "")))

        # NVD data (prefer for CVSS, dates, CWEs)
        for nvd in nvd_group:
            if not summary:
                summary = get_en_description(nvd)
            published_date = published_date or nvd.get("published")
            modified_date = modified_date or nvd.get("lastModified")
            cwe_ids.update(get_nvd_cwes(nvd))

        # CVSS records
        all_cvss = []
        for osv in osv_group:
            all_cvss.extend(extract_osv_cvss(osv))
        for nvd in nvd_group:
            all_cvss.extend(extract_nvd_cvss(nvd))

        # Best CVSS for vuln summary
        best = pick_best_cvss(all_cvss)

        vuln_rows.append({
            "vuln_id": vuln_id,
            "aliases": json.dumps(aliases),
            "summary": summary,
            "details": details,
            "cwe_ids": json.dumps(sorted(cwe_ids)),
            "cvss_base_score": best["base_score"] if best else None,
            "cvss_severity": best["base_severity"] if best else None,
            "cvss_vector": best["vector_string"] if best else None,
            "cvss_version": best["cvss_version"] if best else None,
            "published_date": published_date,
            "modified_date": modified_date,
            "source_datasets": json.dumps(sources),
        })

        # CVSS rows (deduplicate by version+source)
        seen = set()
        for rec in all_cvss:
            key = (rec["cvss_version"], rec.get("source", ""))
            if key in seen:
                continue
            seen.add(key)
            rec["vuln_id"] = vuln_id
            cvss_rows.append(rec)

    vuln_df = pd.DataFrame(vuln_rows)
    cvss_df = pd.DataFrame(cvss_rows)
    return vuln_df, cvss_df, uf


# ---------- Main ----------

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    osv_raw_dir = PROJECT_ROOT / "data" / "osv" / "raw"
    nvd_json = PROJECT_ROOT / "data" / "nvd" / "raw" / "nvd_cves.json"

    osv_entries = load_osv_entries(osv_raw_dir)
    nvd_entries = load_nvd_entries(nvd_json)

    # Build vulnerabilities + cvss
    vuln_df, cvss_df, uf = build_vuln_and_cvss_tables(osv_entries, nvd_entries)
    vuln_df.to_csv(OUTPUT_DIR / "vulnerabilities.csv", **CSV_OPTS)
    log.info("vulnerabilities.csv: %d rows", len(vuln_df))
    cvss_df.to_csv(OUTPUT_DIR / "cvss.csv", **CSV_OPTS)
    log.info("cvss.csv: %d rows", len(cvss_df))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run and verify output**

Run:
```bash
python3 scripts/build_tables.py
```

Expected: `dataset/v2/vulnerabilities.csv` and `dataset/v2/cvss.csv` created. Check:
```bash
python3 -c "
import pandas as pd
v = pd.read_csv('dataset/v2/vulnerabilities.csv', escapechar='\\\\', nrows=5)
print('Vuln columns:', list(v.columns))
print('Rows:', len(pd.read_csv('dataset/v2/vulnerabilities.csv', escapechar='\\\\')))
c = pd.read_csv('dataset/v2/cvss.csv', escapechar='\\\\', nrows=5)
print('CVSS columns:', list(c.columns))
"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/build_tables.py
git commit -m "feat: add build_tables.py — vulnerabilities + cvss table generation"
```

---

### Task 3: Add affected_packages and references tables to `build_tables.py`

Extend `build_tables.py` to also output `affected_packages.csv` and `references.csv`.

**Files:**
- Modify: `scripts/build_tables.py`

- [ ] **Step 1: Add affected_packages extraction**

Add this function to `build_tables.py` (before `main()`):

```python
def build_affected_packages(osv_entries, uf):
    """Build affected_packages.csv from OSV entries."""
    rows = []
    for entry in osv_entries:
        entry_id = entry.get("id", "")
        vuln_id = uf.find(entry_id)
        # Prefer CVE as canonical
        for m in sorted(uf.groups().get(uf.find(entry_id), set())):
            if m.startswith("CVE-"):
                vuln_id = m
                break

        for affected in entry.get("affected", []):
            pkg = affected.get("package", {})
            package_name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", entry.get("_ecosystem", ""))
            purl = pkg.get("purl", "")

            versions_affected = affected.get("versions")

            for rng in affected.get("ranges", []):
                range_type = rng.get("type", "")
                # OSV ranges can have multiple introduced/fixed pairs:
                # [{"introduced":"1.0"},{"fixed":"1.5"},{"introduced":"2.0"},{"fixed":"2.3"}]
                # We emit one row per introduced/fixed pair.
                introduced = ""
                for event in rng.get("events", []):
                    if "introduced" in event:
                        # If we had a pending introduced without a fixed, emit it first
                        if introduced:
                            rows.append({
                                "vuln_id": vuln_id, "package_name": package_name,
                                "ecosystem": ecosystem, "purl": purl,
                                "range_type": range_type,
                                "version_introduced": introduced, "version_fixed": "",
                                "versions_affected": json.dumps(versions_affected) if versions_affected else None,
                            })
                        introduced = event["introduced"]
                    elif "fixed" in event:
                        rows.append({
                            "vuln_id": vuln_id, "package_name": package_name,
                            "ecosystem": ecosystem, "purl": purl,
                            "range_type": range_type,
                            "version_introduced": introduced, "version_fixed": event["fixed"],
                            "versions_affected": json.dumps(versions_affected) if versions_affected else None,
                        })
                        introduced = ""
                    elif "last_affected" in event:
                        rows.append({
                            "vuln_id": vuln_id, "package_name": package_name,
                            "ecosystem": ecosystem, "purl": purl,
                            "range_type": range_type,
                            "version_introduced": introduced, "version_fixed": "",
                            "versions_affected": json.dumps(versions_affected) if versions_affected else None,
                        })
                        introduced = ""
                # Emit trailing introduced without fixed (all versions after X are affected)
                if introduced:
                    rows.append({
                        "vuln_id": vuln_id, "package_name": package_name,
                        "ecosystem": ecosystem, "purl": purl,
                        "range_type": range_type,
                        "version_introduced": introduced, "version_fixed": "",
                        "versions_affected": json.dumps(versions_affected) if versions_affected else None,
                    })

            # If no ranges but versions listed, still emit a row
            if not affected.get("ranges") and versions_affected:
                rows.append({
                    "vuln_id": vuln_id,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "purl": purl,
                    "range_type": "",
                    "version_introduced": "",
                    "version_fixed": "",
                    "versions_affected": json.dumps(versions_affected),
                })

    return pd.DataFrame(rows)
```

- [ ] **Step 2: Add references extraction**

Add this function to `build_tables.py`:

```python
def classify_ref_type(url):
    """Classify a reference URL by type based on URL pattern."""
    if not url:
        return "other"
    if re.search(r"github\.com/.*/commit/", url) or re.search(r"gitlab\.com/.*/commit/", url):
        return "commit"
    if re.search(r"github\.com/.*/issues/", url) or re.search(r"gitlab\.com/.*/issues/", url):
        return "issue"
    if re.search(r"github\.com/.*/pull/", url) or re.search(r"gitlab\.com/.*merge_requests/", url):
        return "pull_request"
    if "advisory" in url.lower() or "ghsa" in url.lower() or "cve.org" in url:
        return "advisory"
    return "other"


def extract_host(url):
    """Extract hostname from URL."""
    match = re.match(r"https?://([^/]+)", url)
    return match.group(1) if match else None


def build_references(osv_entries, nvd_entries, uf):
    """Build references.csv from OSV + NVD entries."""
    rows = []
    seen = set()

    # Helper to resolve canonical vuln_id
    groups = uf.groups()
    def get_canonical(entry_id):
        root = uf.find(entry_id)
        for m in sorted(groups.get(root, set())):
            if m.startswith("CVE-"):
                return m
        return root

    # OSV references
    for entry in osv_entries:
        vuln_id = get_canonical(entry.get("id", ""))
        for ref in entry.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
            key = (vuln_id, url, "osv")
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "vuln_id": vuln_id,
                "url": url,
                "osv_ref_type": ref.get("type"),
                "source": None,
                "tags": None,
                "ref_type": classify_ref_type(url),
                "host": extract_host(url),
            })

    # NVD references
    for cve in nvd_entries:
        vuln_id = get_canonical(cve.get("id", ""))
        for ref in cve.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
            source = ref.get("source")
            key = (vuln_id, url, source or "nvd")
            if key in seen:
                continue
            seen.add(key)
            tags = ref.get("tags")
            rows.append({
                "vuln_id": vuln_id,
                "url": url,
                "osv_ref_type": None,
                "source": source,
                "tags": json.dumps(tags) if tags else None,
                "ref_type": classify_ref_type(url),
                "host": extract_host(url),
            })

    return pd.DataFrame(rows)
```

- [ ] **Step 3: Update `main()` to call these functions and save outputs**

Update `main()` to pass the union-find to the new functions and save the extra tables:

```python
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    osv_raw_dir = PROJECT_ROOT / "data" / "osv" / "raw"
    nvd_json = PROJECT_ROOT / "data" / "nvd" / "raw" / "nvd_cves.json"

    osv_entries = load_osv_entries(osv_raw_dir)
    nvd_entries = load_nvd_entries(nvd_json)

    # Build vulnerabilities + cvss (also returns union-find for reuse)
    vuln_df, cvss_df, uf = build_vuln_and_cvss_tables(osv_entries, nvd_entries)
    vuln_df.to_csv(OUTPUT_DIR / "vulnerabilities.csv", **CSV_OPTS)
    log.info("vulnerabilities.csv: %d rows", len(vuln_df))
    cvss_df.to_csv(OUTPUT_DIR / "cvss.csv", **CSV_OPTS)
    log.info("cvss.csv: %d rows", len(cvss_df))

    # Build affected_packages
    pkg_df = build_affected_packages(osv_entries, uf)
    pkg_df.to_csv(OUTPUT_DIR / "affected_packages.csv", **CSV_OPTS)
    log.info("affected_packages.csv: %d rows", len(pkg_df))

    # Build references
    refs_df = build_references(osv_entries, nvd_entries, uf)
    refs_df.to_csv(OUTPUT_DIR / "references.csv", **CSV_OPTS)
    log.info("references.csv: %d rows", len(refs_df))
```

**Important:** Also update `build_vuln_and_cvss_tables` to `return vuln_df, cvss_df, uf` (add `uf` to the return).

- [ ] **Step 4: Run and verify**

Run: `python3 scripts/build_tables.py`

Check:
```bash
python3 -c "
import pandas as pd
for t in ('vulnerabilities', 'cvss', 'affected_packages', 'references'):
    df = pd.read_csv(f'dataset/v2/{t}.csv', escapechar='\\\\', nrows=0)
    print(f'{t}: {list(df.columns)}')
"
```

Expected: All 4 CSVs exist with correct column names.

- [ ] **Step 5: Commit**

```bash
git add scripts/build_tables.py
git commit -m "feat: add affected_packages + references table generation"
```

---

### Task 4: Extend `github_data.py` to extract new commit fields and output files table

Add `committer_name`, `committer_date`, `is_merge`, `is_signed` extraction. Output a separate `files.csv`.

**Files:**
- Modify: `scripts/github_data.py`

- [ ] **Step 1: Update the `metadata()` function**

Replace the entire `metadata()` function in `scripts/github_data.py` with an updated version that:
1. Fixes the `return df` bug (line 59) → `return git, df`
2. Extracts `committer_name`, `committer_date`, `is_merge`, `is_signed`
3. Writes files to a separate CSV instead of a stringified dict column
4. Uses ISO 8601 dates
5. Uses JSON arrays for comments and parents
6. Moves `stats`/`files` access inside the try block

The key changes to the commit metadata extraction (inside the `for idx, row` loop):

```python
# After getting the commit object:
commit = chain_ord[chain_idx]

# Author info
df.loc[idx, 'message'] = commit.commit.message.strip()
df.loc[idx, 'author_name'] = commit.commit.author.name.strip()
df.loc[idx, 'author_date'] = commit.commit.author.date.isoformat() + "Z"

# Committer info (new)
df.loc[idx, 'committer_name'] = commit.commit.committer.name.strip()
df.loc[idx, 'committer_date'] = commit.commit.committer.date.isoformat() + "Z"

# Merge and signature detection (new)
df.loc[idx, 'is_merge'] = len(commit.commit.parents) > 1
verification = getattr(commit.commit, 'verification', None)
df.loc[idx, 'is_signed'] = bool(verification.verified) if verification else False

# Parents as JSON array
parents = [p.sha for p in commit.commit.parents]
df.loc[idx, 'parents'] = json.dumps(parents)

# Stats
df.loc[idx, 'additions'] = commit.stats.additions
df.loc[idx, 'deletions'] = commit.stats.deletions
df.loc[idx, 'files_changed'] = len(commit.files)

# Comments as JSON array (new format)
comments = []
for comment in commit.get_comments():
    comments.append({
        "author": comment.user.login,
        "date": comment.created_at.isoformat() + "Z",
        "body": comment.body.strip()
    })
df.loc[idx, 'comments'] = json.dumps(comments) if comments else None

# Files — append to files_rows list for separate CSV
for f in commit.files:
    files_rows.append({
        "commit_sha": row['commit_sha'],
        "filename": f.filename,
        "additions": f.additions,
        "deletions": f.deletions,
        "changes": f.changes,
        "status": f.status,
        "previous_filename": getattr(f, 'previous_filename', None),
        "patch": f.patch.strip() if f.patch else None,
    })
```

The `files_rows` list should be initialized before the repo loop and returned alongside the dataframe.

- [ ] **Step 2: Verify the changes compile**

Run: `cd scripts && python3 -c "import github_data; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add scripts/github_data.py
git commit -m "feat: extract committer/merge/signed fields, output files separately"
```

---

### Task 5: Update `pipeline.py` enrich phase for new data model

Update the enrich phase to produce `dataset/v2/commits.csv` and `dataset/v2/files.csv` using the extended metadata.

**Files:**
- Modify: `scripts/pipeline.py`
- Modify: `scripts/cli.py`

- [ ] **Step 1: Update `cli.py` `merge_sources()` to handle missing sources gracefully**

Change the merge function to skip missing source files instead of crashing:

```python
def merge_sources(folder):
    dfs = []
    for source in ("cve-details", "osv", "nvd"):
        path = f"commits/{source}.csv"
        if os.path.exists(path):
            dfs.append(pd.read_csv(path, escapechar="\\"))
        else:
            print(f"Skipping {path} (not found)")
    if not dfs:
        print("No source files found!")
        return
    df = pd.concat(dfs, ignore_index=True)
    print(f"Total number of entries: {len(df)}")
    df.to_csv(
        f"{folder}/sources_commits.csv",
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )
```

Add `import os` at the top of `cli.py` if not present.

- [ ] **Step 2: Update `pipeline.py` enrich phase to output to `dataset/v2/`**

Update the `enrich()` function. The key integration challenge: the old pipeline produces a flat DataFrame with stringified `files`/`stats` columns. We need to:
1. Run `build_tables.py` for vulnerability-side tables
2. Run existing process/merge flow for commit extraction
3. Run metadata fetch with the extended `github_data.py` (which now returns `files_rows`)
4. Transform the commit DataFrame columns to match `commits.csv` schema
5. Write `commits.csv` and `files.csv` to `dataset/v2/`

Replace the `enrich()` function:

```python
def enrich():
    """Merge sources, deduplicate, fetch GitHub metadata, output v2 tables."""
    log.info("=== Enrichment phase ===")

    v2_dir = DATASET_DIR / "v2"
    v2_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Build vulnerability-side tables
    log.info("Building vulnerability tables...")
    subprocess.run([
        sys.executable, str(PROJECT_ROOT / "scripts" / "build_tables.py"),
    ], check=True)

    # Step 2: Copy filtered data to sources/
    sources_dir = PROJECT_ROOT / "sources"
    sources_dir.mkdir(exist_ok=True)
    for source in ("nvd", "osv"):
        src = DATA_DIR / source / f"github-{source}-patches.csv"
        dst = sources_dir / f"{source}.csv"
        if src.exists():
            shutil.copy2(src, dst)
            log.info("Copied %s -> %s", src, dst)

    # Step 3: Run existing process + merge
    log.info("Processing and normalizing sources...")
    commits_dir = PROJECT_ROOT / "commits"
    commits_dir.mkdir(exist_ok=True)
    subprocess.run([
        sys.executable, str(PROJECT_ROOT / "scripts" / "cli.py"),
        "--task=process", f"--folder={commits_dir}",
    ], check=True)

    log.info("Merging datasets...")
    subprocess.run([
        sys.executable, str(PROJECT_ROOT / "scripts" / "cli.py"),
        "--task=merge", f"--folder={DATASET_DIR}",
    ], check=True)

    # Step 4: Fetch GitHub metadata (extended version outputs files_rows)
    sources_csv = DATASET_DIR / "sources_commits.csv"
    log.info("Fetching GitHub metadata...")
    subprocess.run([
        sys.executable, str(PROJECT_ROOT / "scripts" / "cli.py"),
        "--task=metadata",
        f"--fin={sources_csv}",
        f"--folder={DATASET_DIR}",
    ], check=True)

    # Step 5: Transform to v2 schema
    log.info("Transforming to v2 commits schema...")
    metadata_csv = DATASET_DIR / "sources_commits_metadata.csv"
    df = pd.read_csv(metadata_csv, escapechar="\\")

    # Rename columns to match commits.csv spec
    rename_map = {
        "author": "author_name",
        "commit_datetime": "author_date",
        "patch": "patch_type",
        "commit_href": "commit_url",
        "chain_ord_pos": "chain_position",
        "chain_len": "chain_length",
        "before_first_fix_commit": "parents",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    # Select commits.csv columns (what's available from the old pipeline)
    commit_cols = [
        "commit_sha", "vuln_id", "project", "commit_url", "patch_type",
        "chain_length", "chain_position", "message", "author_name", "author_date",
        "committer_name", "committer_date", "is_merge", "is_signed",
        "parents", "additions", "deletions", "files_changed", "comments", "dataset",
    ]
    commits_out = df[[c for c in commit_cols if c in df.columns]]
    commits_out.to_csv(v2_dir / "commits.csv", quoting=csv.QUOTE_NONNUMERIC,
                       escapechar="\\", doublequote=False, index=False)
    log.info("commits.csv: %d rows", len(commits_out))

    # Step 6: Build files.csv from files_output if available
    files_csv = DATASET_DIR / "files_raw.csv"
    if files_csv.exists():
        derive_file_features(str(files_csv))
        shutil.copy2(files_csv, v2_dir / "files.csv")
        log.info("files.csv created")
    else:
        log.warning("files_raw.csv not found — files.csv will be empty")

    update_phase_timestamp("enrich")
```

**Note:** The `github_data.py` metadata function (updated in Task 4) should save `files_rows` to `{folder}/files_raw.csv` alongside the main metadata CSV. The implementer should add this to the `get_metadata()` function in `cli.py` after the `github_data.metadata()` call.

- [ ] **Step 3: Update `pipeline.py` to add file-level feature derivation**

After the metadata step produces files data, add extension/language/is_test_file derivation using `features.py` ext_map:

```python
def derive_file_features(files_csv):
    """Add extension, language, is_test_file to files.csv."""
    import re
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from features import ext_map, get_extension, get_key

    test_patterns = re.compile(
        r"(^|/)tests?/|test_[^/]+\.\w+$|[^/]+_test\.\w+$|[^/]+_spec\.\w+$|"
        r"(^|/)spec/|(^|/)__tests__/|(^|/)testing/"
    )

    df = pd.read_csv(files_csv, escapechar="\\")
    df["extension"] = df["filename"].apply(
        lambda f: "." + f.rsplit(".", 1)[-1].lower() if "." in f else ""
    )
    df["language"] = df["extension"].apply(
        lambda ext: get_key(ext.lstrip(".")) if ext else None
    )
    df["is_test_file"] = df["filename"].apply(
        lambda f: bool(test_patterns.search(f))
    )
    df.to_csv(files_csv, **CSV_OPTS)
```

- [ ] **Step 4: Commit**

```bash
git add scripts/pipeline.py scripts/cli.py
git commit -m "feat: update enrich phase for v2 data model"
```

---

### Task 6: Build the flat convenience view

New curate step that joins vulnerabilities + commits to produce `security_patches_v2.0.csv`.

**Files:**
- Modify: `scripts/pipeline.py` (update `curate()` function)

- [ ] **Step 1: Rewrite the curate function**

```python
def curate():
    """Build flat convenience view from relational tables."""
    log.info("=== Curation phase ===")

    v2_dir = DATASET_DIR / "v2"
    vulns = pd.read_csv(v2_dir / "vulnerabilities.csv", escapechar="\\")
    commits = pd.read_csv(v2_dir / "commits.csv", escapechar="\\")
    files = pd.read_csv(v2_dir / "files.csv", escapechar="\\")

    # Compute primary_language per commit (most lines changed, alphabetical tiebreak)
    file_lang = files.dropna(subset=["language"]).copy()
    file_lang["total_lines"] = file_lang["additions"] + file_lang["deletions"]
    lang_totals = file_lang.groupby(["commit_sha", "language"])["total_lines"].sum().reset_index()
    lang_totals = lang_totals.sort_values(
        ["commit_sha", "total_lines", "language"],
        ascending=[True, False, True]
    )
    primary_lang = lang_totals.drop_duplicates(subset="commit_sha", keep="first")[
        ["commit_sha", "language"]
    ].rename(columns={"language": "primary_language"})

    # Join
    flat = commits.merge(vulns[["vuln_id", "cwe_ids", "cvss_base_score", "cvss_severity",
                                 "summary", "published_date"]], on="vuln_id", how="left")
    flat = flat.merge(primary_lang, on="commit_sha", how="left")

    # Select and order columns
    cols = [
        "vuln_id", "cwe_ids", "cvss_base_score", "cvss_severity", "summary",
        "published_date", "project", "commit_sha", "message", "author_name",
        "author_date", "patch_type", "additions", "deletions", "files_changed",
        "primary_language", "dataset",
    ]
    flat = flat[[c for c in cols if c in flat.columns]]

    out_path = DATASET_DIR / "security_patches_v2.0.csv"
    flat.to_csv(out_path, quoting=csv.QUOTE_NONNUMERIC, escapechar="\\",
                doublequote=False, index=False)
    log.info("Flat view: %d rows -> %s", len(flat), out_path)
    log.info("Unique vulns: %d", flat["vuln_id"].nunique())

    update_phase_timestamp("curate")
```

- [ ] **Step 2: Run and verify**

Run: `python3 scripts/pipeline.py curate`

Check:
```bash
python3 -c "
import pandas as pd
df = pd.read_csv('dataset/security_patches_v2.0.csv', escapechar='\\\\', nrows=5)
print('Columns:', list(df.columns))
print(df[['vuln_id', 'commit_sha', 'primary_language']].head())
"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/pipeline.py
git commit -m "feat: add flat convenience view curation step"
```

---

### Task 7: Run full pipeline end-to-end and fix issues

Execute the full enriched pipeline and fix any issues that arise.

**Files:**
- Potentially any file from Tasks 1-6

- [ ] **Step 1: Run build_tables.py**

```bash
python3 scripts/build_tables.py
```

Verify all 4 vulnerability-side tables in `dataset/v2/`.

- [ ] **Step 2: Run enrich phase**

```bash
python3 scripts/pipeline.py enrich
```

This is the longest step (GitHub API). Verify `dataset/v2/commits.csv` and `dataset/v2/files.csv`.

- [ ] **Step 3: Run curate phase**

```bash
python3 scripts/pipeline.py curate
```

Verify `dataset/security_patches_v2.0.csv`.

- [ ] **Step 4: Validate all tables**

```bash
python3 -c "
import pandas as pd
tables = {
    'vulnerabilities': 'dataset/v2/vulnerabilities.csv',
    'cvss': 'dataset/v2/cvss.csv',
    'affected_packages': 'dataset/v2/affected_packages.csv',
    'references': 'dataset/v2/references.csv',
    'commits': 'dataset/v2/commits.csv',
    'files': 'dataset/v2/files.csv',
    'flat_view': 'dataset/security_patches_v2.0.csv',
}
for name, path in tables.items():
    try:
        df = pd.read_csv(path, escapechar='\\\\')
        print(f'{name}: {len(df)} rows, {len(df.columns)} cols')
    except Exception as e:
        print(f'{name}: MISSING or ERROR - {e}')
"
```

- [ ] **Step 5: Fix any issues found, commit**

```bash
git add -A
git commit -m "fix: resolve end-to-end pipeline issues"
```

- [ ] **Step 6: Final commit with all tables**

```bash
git add dataset/v2/ dataset/security_patches_v2.0.csv
git commit -m "data: generate v2 relational dataset + flat convenience view"
```

---

### Task 8: Update documentation

Update README and pipeline docs to reflect the new data model.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Add a "Dataset v2.0 Schema" section after the Quick Start, documenting all 7 output files with column descriptions.

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document v2 relational data model in README"
```
