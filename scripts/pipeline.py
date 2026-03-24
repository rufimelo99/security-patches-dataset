#!/usr/bin/env python3
"""Security Patches Dataset Pipeline v2.

Usage:
    python scripts/pipeline.py collect [--source osv|nvd|all]
    python scripts/pipeline.py process [--source osv|nvd|all]
    python scripts/pipeline.py enrich
    python scripts/pipeline.py curate
    python scripts/pipeline.py run          # all phases
"""
import argparse
import csv
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from lib.config import (
    update_phase_timestamp,
    get_phase_timestamp,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

DATA_DIR = PROJECT_ROOT / "data"
DATASET_DIR = PROJECT_ROOT / "dataset"
TOOLS_DIR = PROJECT_ROOT / "tools"


# --- Phase 1: Collect ---

def collect_osv():
    """Download and extract OSV vulnerability data."""
    log.info("=== Collecting OSV data ===")
    osv_raw_dir = DATA_DIR / "osv" / "raw"
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "osv" / "download.py"),
        "-o", str(osv_raw_dir),
        "--csv-out", "raw-osv-data.csv",
    ]
    subprocess.run(cmd, check=True)
    update_phase_timestamp("collect_osv")


def collect_nvd():
    """Download CVE data from NVD API 2.0."""
    log.info("=== Collecting NVD data ===")
    nvd_raw_dir = DATA_DIR / "nvd" / "raw"

    cmd = [
        sys.executable,
        str(TOOLS_DIR / "nvd" / "download.py"),
        "-o", str(nvd_raw_dir),
    ]

    # Check for incremental update
    last_run = get_phase_timestamp("collect_nvd")
    if last_run:
        log.info("Incremental update from %s", last_run)
        cmd.extend(["--last-modified-start", last_run])

    subprocess.run(cmd, check=True)

    # Process the raw JSON into CSV
    nvd_json = nvd_raw_dir / "nvd_cves.json"
    nvd_csv = DATA_DIR / "nvd" / "raw-nvd-data.csv"
    proc_cmd = [
        sys.executable,
        str(TOOLS_DIR / "nvd" / "process.py"),
        "--input", str(nvd_json),
        "--output", str(nvd_csv),
    ]
    subprocess.run(proc_cmd, check=True)
    update_phase_timestamp("collect_nvd")


def collect(source="all"):
    """Run the collect phase."""
    if source in ("osv", "all"):
        collect_osv()
    if source in ("nvd", "all"):
        collect_nvd()


# --- Phase 2: Process ---

def process_source(source_name):
    """Extract commit references and normalize for a given source."""
    log.info("=== Processing %s ===", source_name)
    data_dir = DATA_DIR / source_name
    # OSV raw CSV is inside raw/ subdir; NVD is at the source level
    if source_name == "osv":
        raw_csv = data_dir / "raw" / f"raw-{source_name}-data.csv"
    else:
        raw_csv = data_dir / f"raw-{source_name}-data.csv"
    patches_csv = data_dir / f"all-{source_name}-patches.csv"

    refs_script = str(TOOLS_DIR / "common" / "references.py")

    # Extract commit references
    log.info("Extracting commit references...")
    subprocess.run([
        sys.executable, refs_script,
        "--task=commits",
        f"--fin={raw_csv}",
        f"--fout={patches_csv}",
    ], check=True)

    # Normalize commits
    log.info("Normalizing commits...")
    subprocess.run([
        sys.executable, refs_script,
        "--task=normalize",
        f"--fin={patches_csv}",
    ], check=True)

    # Filter for GitHub
    log.info("Filtering for GitHub commits...")
    subprocess.run([
        sys.executable, refs_script,
        "--task=filter",
        f"--fin={patches_csv}",
        f"--source=github",
        f"--dataset={source_name}",
    ], check=True)

    update_phase_timestamp(f"process_{source_name}")


def process(source="all"):
    """Run the process phase."""
    if source in ("osv", "all"):
        process_source("osv")
    if source in ("nvd", "all"):
        process_source("nvd")


# --- Phase 3: Enrich ---

def derive_file_features(input_csv, output_csv):
    """Add extension, language, is_test_file to files data."""
    import re as _re
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from features import get_key

    test_patterns = _re.compile(
        r"(^|/)tests?/|test_[^/]+\.\w+$|[^/]+_test\.\w+$|[^/]+_spec\.\w+$|"
        r"(^|/)spec/|(^|/)__tests__/|(^|/)testing/"
    )

    df = pd.read_csv(input_csv, escapechar="\\")
    df["extension"] = df["filename"].apply(
        lambda f: "." + f.rsplit(".", 1)[-1].lower() if "." in str(f) else ""
    )
    df["language"] = df["extension"].apply(
        lambda ext: get_key(ext.lstrip(".")) if ext else None
    )
    df["is_test_file"] = df["filename"].apply(
        lambda f: bool(test_patterns.search(str(f)))
    )
    df.to_csv(output_csv, quoting=csv.QUOTE_NONNUMERIC, escapechar="\\",
              doublequote=False, index=False)


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

    # Step 4: Fetch GitHub metadata
    sources_csv = DATASET_DIR / "sources_commits.csv"
    log.info("Fetching GitHub metadata...")
    subprocess.run([
        sys.executable, str(PROJECT_ROOT / "scripts" / "cli.py"),
        "--task=metadata",
        f"--fin={sources_csv}",
        f"--folder={DATASET_DIR}",
    ], check=True)

    # Step 5: Transform to v2 commits schema
    log.info("Transforming to v2 commits schema...")
    metadata_csv = DATASET_DIR / "sources_commits_metadata.csv"
    df = pd.read_csv(metadata_csv, escapechar="\\")

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

    # Step 6: Build files.csv with derived features
    files_csv = DATASET_DIR / "files_raw.csv"
    if files_csv.exists():
        derive_file_features(str(files_csv), str(v2_dir / "files.csv"))
        log.info("files.csv created")
    else:
        log.warning("files_raw.csv not found — files.csv will be empty")

    update_phase_timestamp("enrich")


# --- Phase 4: Curate ---

def curate():
    """Build flat convenience view from relational tables."""
    log.info("=== Curation phase ===")

    v2_dir = DATASET_DIR / "v2"

    vulns = pd.read_csv(v2_dir / "vulnerabilities.csv", escapechar="\\")
    commits = pd.read_csv(v2_dir / "commits.csv", escapechar="\\")

    files_path = v2_dir / "files.csv"
    if files_path.exists():
        files = pd.read_csv(files_path, escapechar="\\")

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
    else:
        log.warning("files.csv not found — primary_language will be empty")
        primary_lang = pd.DataFrame(columns=["commit_sha", "primary_language"])

    # Join
    flat = commits.merge(
        vulns[["vuln_id", "cwe_ids", "cvss_base_score", "cvss_severity", "summary", "published_date"]],
        on="vuln_id", how="left"
    )
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
    if "vuln_id" in flat.columns:
        log.info("Unique vulns: %d", flat["vuln_id"].nunique())

    update_phase_timestamp("curate")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Security Patches Dataset Pipeline v2"
    )
    sub = parser.add_subparsers(dest="phase", required=True)

    # collect
    p_collect = sub.add_parser("collect", help="Download raw vulnerability data")
    p_collect.add_argument("--source", choices=["osv", "nvd", "all"], default="all")

    # process
    p_process = sub.add_parser("process", help="Extract and normalize commit references")
    p_process.add_argument("--source", choices=["osv", "nvd", "all"], default="all")

    # enrich
    sub.add_parser("enrich", help="Merge, deduplicate, fetch GitHub metadata")

    # curate
    sub.add_parser("curate", help="Clean and produce final dataset")

    # run (all phases)
    p_run = sub.add_parser("run", help="Run all phases end-to-end")
    p_run.add_argument("--source", choices=["osv", "nvd", "all"], default="all")

    args = parser.parse_args()

    if args.phase == "collect":
        collect(args.source)
    elif args.phase == "process":
        process(args.source)
    elif args.phase == "enrich":
        enrich()
    elif args.phase == "curate":
        curate()
    elif args.phase == "run":
        collect(args.source)
        process(args.source)
        enrich()
        curate()


if __name__ == "__main__":
    main()
