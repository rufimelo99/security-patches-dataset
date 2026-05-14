"""Tests for scripts/lib/upsert.py.

Run with: python -m pytest tests/test_upsert.py
Or standalone: python tests/test_upsert.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lib.upsert import upsert_csv, replace_csv, write_changelog  # noqa: E402


def _read(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, escapechar="\\", dtype=str, keep_default_na=False)


def test_empty_target_all_inserted(tmp_path):
    target = tmp_path / "vulns.csv"
    delta = pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
        {"vuln_id": "CVE-2024-2", "severity": "LOW"},
    ])

    result = upsert_csv(target, delta, key_cols=["vuln_id"])

    assert result.n_inserted == 2
    assert result.n_updated == 0
    assert result.unchanged == 0
    assert set(result.inserted) == {("CVE-2024-1",), ("CVE-2024-2",)}
    assert len(_read(target)) == 2


def test_unchanged_rows_detected(tmp_path):
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
    ]), key_cols=["vuln_id"])

    result = upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
    ]), key_cols=["vuln_id"])

    assert result.n_inserted == 0
    assert result.n_updated == 0
    assert result.unchanged == 1


def test_updated_rows_detected(tmp_path):
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
        {"vuln_id": "CVE-2024-2", "severity": "LOW"},
    ]), key_cols=["vuln_id"])

    result = upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "CRITICAL"},  # changed
        {"vuln_id": "CVE-2024-2", "severity": "LOW"},       # unchanged
        {"vuln_id": "CVE-2024-3", "severity": "MEDIUM"},    # new
    ]), key_cols=["vuln_id"])

    assert result.inserted == [("CVE-2024-3",)]
    assert result.updated == [("CVE-2024-1",)]
    assert result.unchanged == 1

    merged = _read(target)
    assert len(merged) == 3
    assert merged[merged["vuln_id"] == "CVE-2024-1"]["severity"].iloc[0] == "CRITICAL"


def test_composite_key(tmp_path):
    target = tmp_path / "commits.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "aaa", "additions": "10"},
        {"vuln_id": "CVE-2024-1", "commit_sha": "bbb", "additions": "5"},
    ]), key_cols=["vuln_id", "commit_sha"])

    result = upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "commit_sha": "aaa", "additions": "20"},  # updated
        {"vuln_id": "CVE-2024-1", "commit_sha": "ccc", "additions": "7"},   # inserted
    ]), key_cols=["vuln_id", "commit_sha"])

    assert result.updated == [("CVE-2024-1", "aaa")]
    assert result.inserted == [("CVE-2024-1", "ccc")]
    assert result.unchanged == 0
    assert len(_read(target)) == 3


def test_compare_cols_restricts_update_detection(tmp_path):
    """If only severity is in compare_cols, changes to other fields should
    not be flagged as updates (they're still written, but counted unchanged).
    """
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH", "summary": "old"},
    ]), key_cols=["vuln_id"])

    result = upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH", "summary": "new"},
    ]), key_cols=["vuln_id"], compare_cols=["severity"])

    assert result.n_updated == 0
    assert result.unchanged == 1
    # summary is still overwritten because full delta row replaces the target row.
    assert _read(target)["summary"].iloc[0] == "new"


def test_atomic_write_no_tmp_leftover(tmp_path):
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
    ]), key_cols=["vuln_id"])
    assert not (tmp_path / "vulns.csv.tmp").exists()


def test_replace_detects_removed_rows(tmp_path):
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
        {"vuln_id": "CVE-2024-2", "severity": "LOW"},
        {"vuln_id": "CVE-2024-3", "severity": "MEDIUM"},
    ]), key_cols=["vuln_id"])

    # New authoritative state: drop CVE-2024-2, bump CVE-2024-1, keep CVE-2024-3, add CVE-2024-4.
    result = replace_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "CRITICAL"},
        {"vuln_id": "CVE-2024-3", "severity": "MEDIUM"},
        {"vuln_id": "CVE-2024-4", "severity": "LOW"},
    ]), key_cols=["vuln_id"])

    assert result.inserted == [("CVE-2024-4",)]
    assert result.updated == [("CVE-2024-1",)]
    assert result.removed == [("CVE-2024-2",)]
    assert result.unchanged == 1

    merged = _read(target)
    assert set(merged["vuln_id"]) == {"CVE-2024-1", "CVE-2024-3", "CVE-2024-4"}


def test_replace_writes_only_new_state(tmp_path):
    target = tmp_path / "vulns.csv"
    upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
    ]), key_cols=["vuln_id"])

    replace_csv(target, pd.DataFrame(columns=["vuln_id", "severity"]), key_cols=["vuln_id"])
    assert len(_read(target)) == 0


def test_changelog_written(tmp_path):
    target = tmp_path / "vulns.csv"
    result = upsert_csv(target, pd.DataFrame([
        {"vuln_id": "CVE-2024-1", "severity": "HIGH"},
    ]), key_cols=["vuln_id"])

    log_path = write_changelog(tmp_path, phase="enrich", results=[result])
    assert log_path.exists()
    content = log_path.read_text().strip()
    assert "CVE-2024-1" in content
    assert '"phase": "enrich"' in content


if __name__ == "__main__":
    import traceback

    tests = [
        fn for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    from tempfile import TemporaryDirectory

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
