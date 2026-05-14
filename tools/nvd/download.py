#!/usr/bin/env python3
"""Download CVE data from NVD API 2.0.

Supports incremental updates via --last-modified-start.
Rate limit: 5 requests/30s (public) or 50/30s (with API key).
We use 6s delay between requests for safety without API key.
"""
import os
import json
import time
import logging
import argparse
from datetime import datetime, timezone

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
REQUEST_DELAY = 6  # seconds between requests


def fetch_cves(start_index=0, last_mod_start=None, last_mod_end=None, api_key=None):
    """Fetch a page of CVEs from NVD API 2.0."""
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    if last_mod_start and last_mod_end:
        params["lastModStartDate"] = last_mod_start
        params["lastModEndDate"] = last_mod_end

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=120)
    response.raise_for_status()
    return response.json()


def download_all_cves(output_dir, last_mod_start=None, api_key=None, output_file="nvd_cves.json"):
    """Download all CVEs, paginating through the NVD API 2.0."""
    os.makedirs(output_dir, exist_ok=True)

    last_mod_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    start_index = 0
    total_results = None
    all_vulnerabilities = []

    while total_results is None or start_index < total_results:
        log.info("Fetching CVEs starting at index %d...", start_index)

        try:
            data = fetch_cves(
                start_index=start_index,
                last_mod_start=last_mod_start,
                last_mod_end=last_mod_end,
                api_key=api_key,
            )
        except requests.RequestException as e:
            log.error("Request failed at index %d: %s. Retrying in 30s...", start_index, e)
            time.sleep(30)
            continue

        if total_results is None:
            total_results = data.get("totalResults", 0)
            log.info("Total CVEs to fetch: %d", total_results)

        vulnerabilities = data.get("vulnerabilities", [])
        all_vulnerabilities.extend(vulnerabilities)
        start_index += RESULTS_PER_PAGE

        log.info("Fetched %d/%d CVEs", len(all_vulnerabilities), total_results)

        # Save checkpoint every 10 pages
        if len(all_vulnerabilities) % (RESULTS_PER_PAGE * 10) == 0:
            checkpoint_path = os.path.join(output_dir, "checkpoint.json")
            with open(checkpoint_path, "w") as f:
                json.dump(all_vulnerabilities, f)
            log.info("Checkpoint saved: %d CVEs", len(all_vulnerabilities))

        # Respect rate limits
        time.sleep(REQUEST_DELAY)

    # Save final output
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, "w") as f:
        json.dump(all_vulnerabilities, f)
    log.info("Saved %d CVEs to %s", len(all_vulnerabilities), output_path)

    return all_vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="Download CVEs from NVD API 2.0")
    parser.add_argument("-o", "--output-dir", default="../../data/nvd/raw",
                        help="Output directory (default: ../../data/nvd/raw)")
    parser.add_argument("--last-modified-start", default=None,
                        help="ISO datetime for incremental updates (e.g. 2024-01-01T00:00:00.000)")
    parser.add_argument("--api-key", default=None,
                        help="NVD API key for higher rate limits")
    parser.add_argument("--output-file", default="nvd_cves.json",
                        help="Output filename inside --output-dir (default: nvd_cves.json)")
    args = parser.parse_args()

    download_all_cves(args.output_dir, args.last_modified_start, args.api_key,
                      args.output_file)


if __name__ == "__main__":
    main()
