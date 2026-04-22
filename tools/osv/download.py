#!/usr/bin/env python3
import os
import gc
import json
import tempfile
import zipfile
import logging
import argparse
import csv
from datetime import datetime, timezone

import requests
import pandas as pd

from process import process_ecosystem_vulns

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

ECOSYSTEMS = [
    "AlmaLinux", "Alpine", "Android", "Bitnami", "CRAN", "Chainguard",
    "Debian", "GIT", "GSD", "GitHub Actions", "Go", "Hackage", "Hex",
    "Linux", "Maven", "NuGet", "OSS-Fuzz", "Packagist", "Pub", "PyPI",
    "Red Hat", "Rocky Linux", "RubyGems", "SUSE", "SwiftURL", "UVI",
    "Ubuntu", "Wolfi", "crates.io", "npm", "openSUSE",
]

BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"


def download_to_disk(ecosystem, output_dir):
    """Download all.zip for ecosystem, stream to disk, extract, return dir."""
    url = f"{BASE_URL}/{ecosystem}/all.zip"
    log.info("Downloading %s", ecosystem)

    try:
        with requests.get(url, stream=True, timeout=600) as r:
            r.raise_for_status()
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            for chunk in r.iter_content(chunk_size=8 * 1024 * 1024):
                tmp.write(chunk)
            tmp.close()
    except requests.RequestException as e:
        log.error("Failed to download %s: %s", ecosystem, e)
        return None

    ecosystem_dir = os.path.join(output_dir, ecosystem)
    os.makedirs(ecosystem_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(tmp.name) as zf:
            zf.extractall(ecosystem_dir)
    finally:
        os.unlink(tmp.name)

    log.info("Extracted %s", ecosystem)
    return ecosystem_dir


BATCH_SIZE = 5000


def iter_json_batches(ecosystem_dir, batch_size=BATCH_SIZE):
    """Yield batches of parsed JSON dicts from ecosystem_dir."""
    batch = []
    json_files = [f for f in os.listdir(ecosystem_dir) if f.endswith(".json")]
    for filename in json_files:
        file_path = os.path.join(ecosystem_dir, filename)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                batch.append(json.load(f))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Skipping %s: %s", file_path, e)
            continue
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _parse_iso(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime; None on failure."""
    if value is None or value == "" or value != value:  # NaN check
        return None
    s = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def filter_by_modified(df, modified_since):
    """Keep rows whose modified_date is >= modified_since.

    Rows with missing/unparseable modified_date are kept — we cannot prove
    they're stale, and it's safer to re-process than silently drop them.
    """
    if modified_since is None or "modified_date" not in df.columns:
        return df
    cutoff = _parse_iso(modified_since)
    if cutoff is None:
        return df
    parsed = df["modified_date"].map(_parse_iso)
    keep = parsed.isna() | parsed.map(lambda d: d is not None and d >= cutoff)
    return df[keep]


def main():
    parser = argparse.ArgumentParser(
        description="Download OSV vulnerabilities for all ecosystems."
    )
    parser.add_argument("-o", "--output-dir", default="osv_data",
                        help="Directory for downloaded data (default: osv_data).")
    parser.add_argument("--csv-out", default="all_vulns.csv",
                        help="Filename for combined CSV (default: all_vulns.csv).")
    parser.add_argument("--modified-since", default=None,
                        help="ISO datetime. Only rows with modified_date >= this "
                             "value are written (incremental mode).")
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    csv_path = os.path.join(output_dir, args.csv_out)
    # Truncate any previous run's CSV so incremental deltas don't accumulate.
    if os.path.exists(csv_path):
        os.remove(csv_path)

    header_written = False
    total_rows = 0
    total_kept = 0

    # Process one ecosystem at a time to keep memory low
    for eco in ECOSYSTEMS:
        eco_dir = download_to_disk(eco, output_dir)
        if not eco_dir:
            continue

        eco_rows = 0
        eco_kept = 0
        for batch in iter_json_batches(eco_dir):
            batch_df = process_ecosystem_vulns(batch, ecosystem=eco)
            eco_rows += len(batch_df)

            if args.modified_since:
                batch_df = filter_by_modified(batch_df, args.modified_since)
            if len(batch_df) == 0:
                del batch, batch_df
                gc.collect()
                continue

            batch_df.to_csv(csv_path, mode="a", header=not header_written,
                            quoting=csv.QUOTE_NONNUMERIC, escapechar="\\",
                            doublequote=False, index=False)
            header_written = True
            eco_kept += len(batch_df)
            del batch, batch_df
            gc.collect()

        log.info("%s: %d rows processed, %d kept", eco, eco_rows, eco_kept)
        total_rows += eco_rows
        total_kept += eco_kept

    if args.modified_since:
        log.info("Saved %d / %d rows (modified since %s) to %s",
                 total_kept, total_rows, args.modified_since, csv_path)
    else:
        log.info("Saved %d rows to %s", total_kept, csv_path)


if __name__ == "__main__":
    main()
