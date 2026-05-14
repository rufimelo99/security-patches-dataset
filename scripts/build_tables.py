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


# ---------- Affected packages ----------

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


# ---------- References ----------

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


# ---------- Main ----------

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

    return vuln_df, cvss_df, uf


if __name__ == "__main__":
    main()
