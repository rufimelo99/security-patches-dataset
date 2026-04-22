#!/usr/bin/env python3
"""Process NVD API 2.0 JSON into a normalized CSV."""
import os
import json
import csv
import logging
import argparse

import pandas as pd
import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def extract_cve_data(vuln_item):
    """Extract fields from a single NVD API 2.0 vulnerability object."""
    cve = vuln_item.get("cve", {})

    # CVE ID
    cve_id = cve.get("id", np.nan)

    # CWEs
    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.add(val)
    cwes_str = str(cwes) if cwes else np.nan

    # Description (English)
    description = np.nan
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", np.nan)
            break

    # CVSS scores — prefer v3.1, fallback v3.0, then v2.0
    severity = np.nan
    score = np.nan
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            cvss_data = metrics[0].get("cvssData", {})
            score = cvss_data.get("baseScore", np.nan)
            severity = cvss_data.get("baseSeverity", np.nan)
            break

    # Dates
    published_date = cve.get("published", np.nan)
    last_modified_date = cve.get("lastModified", np.nan)

    # References
    refs = set()
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.add(url)
    refs_str = str(refs) if refs else np.nan

    return {
        "cve_id": cve_id,
        "cwes": cwes_str,
        "description": description,
        "severity": severity,
        "score": score,
        "published_date": published_date,
        "last_modified_date": last_modified_date,
        "refs": refs_str,
    }


def process_nvd_json(input_path, output_path):
    """Process NVD API 2.0 JSON file into a CSV."""
    log.info("Loading %s", input_path)
    with open(input_path, "r") as f:
        vulnerabilities = json.load(f)

    log.info("Processing %d CVEs", len(vulnerabilities))
    rows = [extract_cve_data(v) for v in vulnerabilities]
    df = pd.DataFrame(rows)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    df.to_csv(output_path, quoting=csv.QUOTE_NONNUMERIC,
              escapechar="\\", doublequote=False, index=False)
    log.info("Saved %d rows to %s", len(df), output_path)


def main():
    parser = argparse.ArgumentParser(description="Process NVD API 2.0 JSON into CSV")
    parser.add_argument("--input", required=True, help="Path to nvd_cves.json")
    parser.add_argument("--output", default="../../data/nvd/raw-nvd-data.csv",
                        help="Output CSV path")
    args = parser.parse_args()

    process_nvd_json(args.input, args.output)


if __name__ == "__main__":
    main()
