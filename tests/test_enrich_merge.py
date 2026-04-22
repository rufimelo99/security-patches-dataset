"""Tests for pipeline.merge_sources_with_prior_metadata.

Run with: python -m pytest tests/test_enrich_merge.py
Or standalone: python tests/test_enrich_merge.py
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from pipeline import merge_sources_with_prior_metadata  # noqa: E402


def _write(path, df):
    df.to_csv(
        path,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )


def _read(path):
    return pd.read_csv(path, escapechar="\\")


def test_no_prior_passes_sources_through(tmp_path):
    sources = tmp_path / "sources.csv"
    out = tmp_path / "out.csv"
    _write(sources, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y"},
    ]))

    stats = merge_sources_with_prior_metadata(sources, tmp_path / "missing.csv", out)

    assert stats == {"total": 1, "already_processed": 0}
    df = _read(out)
    assert "message" not in df.columns
    assert len(df) == 1


def test_prior_metadata_is_carried_forward(tmp_path):
    sources = tmp_path / "sources.csv"
    prior = tmp_path / "prior.csv"
    out = tmp_path / "out.csv"

    _write(sources, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y"},
        {"vuln_id": "CVE-2024-2", "commit_sha": "def", "project": "x/y"},
    ]))
    _write(prior, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y",
         "message": "fix", "additions": 3, "files": "[...]"},
    ]))

    stats = merge_sources_with_prior_metadata(sources, prior, out)

    assert stats == {"total": 2, "already_processed": 1}
    df = _read(out)
    assert len(df) == 2
    # Row already processed has message filled; the other does not.
    by_sha = df.set_index("commit_sha")
    assert by_sha.loc["abc", "message"] == "fix"
    assert pd.isna(by_sha.loc["def", "message"])


def test_prior_without_matching_keys_preserves_nothing(tmp_path):
    sources = tmp_path / "sources.csv"
    prior = tmp_path / "prior.csv"
    out = tmp_path / "out.csv"

    _write(sources, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y"},
    ]))
    _write(prior, pd.DataFrame([
        {"vuln_id": "CVE-2024-9", "commit_sha": "zzz", "project": "x/y",
         "message": "old"},
    ]))

    stats = merge_sources_with_prior_metadata(sources, prior, out)

    assert stats == {"total": 1, "already_processed": 0}
    df = _read(out)
    assert pd.isna(df["message"].iloc[0])


def test_prior_with_duplicate_keys_kept_once(tmp_path):
    sources = tmp_path / "sources.csv"
    prior = tmp_path / "prior.csv"
    out = tmp_path / "out.csv"

    _write(sources, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y"},
    ]))
    _write(prior, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y", "message": "a"},
        {"vuln_id": "CVE-2024-1", "commit_sha": "abc", "project": "x/y", "message": "b"},
    ]))

    stats = merge_sources_with_prior_metadata(sources, prior, out)

    assert stats == {"total": 1, "already_processed": 1}
    assert len(_read(out)) == 1


if __name__ == "__main__":
    import traceback
    from tempfile import TemporaryDirectory

    tests = [
        fn for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failed = 0
    for fn in tests:
        with TemporaryDirectory() as td:
            try:
                fn(Path(td))
                print(f"PASS {fn.__name__}")
            except Exception:
                failed += 1
                print(f"FAIL {fn.__name__}")
                traceback.print_exc()

    if failed:
        sys.exit(1)
    print(f"\nAll {len(tests)} tests passed.")
