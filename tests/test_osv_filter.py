"""Tests for the OSV `--modified-since` filter.

Run with: python -m pytest tests/test_osv_filter.py
Or standalone: python tests/test_osv_filter.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools" / "osv"))

from download import filter_by_modified, _parse_iso  # noqa: E402


def _df():
    return pd.DataFrame([
        {"vuln_id": "OSV-A", "modified_date": "2026-04-01T00:00:00Z"},
        {"vuln_id": "OSV-B", "modified_date": "2026-04-10T12:00:00Z"},
        {"vuln_id": "OSV-C", "modified_date": "2026-04-14T23:59:59Z"},
        {"vuln_id": "OSV-D", "modified_date": None},
        {"vuln_id": "OSV-E", "modified_date": "garbage"},
    ])


def test_filter_none_returns_original(tmp_path):
    df = _df()
    assert filter_by_modified(df, None) is df


def test_filter_keeps_recent_and_unparseable(tmp_path):
    df = _df()
    out = filter_by_modified(df, "2026-04-05T00:00:00Z")
    ids = set(out["vuln_id"])
    # B and C are after the cutoff; D (None) and E (unparseable) kept to be safe.
    assert ids == {"OSV-B", "OSV-C", "OSV-D", "OSV-E"}


def test_filter_equal_to_cutoff_is_kept(tmp_path):
    df = pd.DataFrame([{"vuln_id": "X", "modified_date": "2026-04-10T00:00:00Z"}])
    out = filter_by_modified(df, "2026-04-10T00:00:00Z")
    assert len(out) == 1


def test_parse_iso_handles_z_suffix(tmp_path):
    dt = _parse_iso("2026-04-10T12:00:00Z")
    assert dt is not None
    assert dt.utcoffset().total_seconds() == 0


def test_parse_iso_naive_becomes_utc(tmp_path):
    dt = _parse_iso("2026-04-10T12:00:00")
    assert dt is not None
    assert dt.utcoffset().total_seconds() == 0


def test_parse_iso_nan(tmp_path):
    assert _parse_iso(np.nan) is None
    assert _parse_iso("") is None
    assert _parse_iso(None) is None


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
