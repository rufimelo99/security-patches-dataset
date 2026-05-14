"""Tests for scripts/lib/nvd_store.merge_nvd_json.

Run with: python -m pytest tests/test_nvd_store.py
Or standalone: python tests/test_nvd_store.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lib.nvd_store import merge_nvd_json  # noqa: E402


def _entry(cve_id, last_mod="2026-04-01T00:00:00Z", severity="HIGH"):
    return {
        "cve": {
            "id": cve_id,
            "lastModified": last_mod,
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]},
        }
    }


def _read(path):
    with open(path) as f:
        return json.load(f)


def test_merge_into_empty_cumulative(tmp_path):
    cumulative = tmp_path / "nvd_cves.json"
    delta = tmp_path / "delta.json"
    with open(delta, "w") as f:
        json.dump([_entry("CVE-2024-1"), _entry("CVE-2024-2")], f)

    inserted, updated = merge_nvd_json(cumulative, delta)

    assert set(inserted) == {"CVE-2024-1", "CVE-2024-2"}
    assert updated == []
    assert len(_read(cumulative)) == 2


def test_merge_adds_new_and_updates_existing(tmp_path):
    cumulative = tmp_path / "nvd_cves.json"
    with open(cumulative, "w") as f:
        json.dump([
            _entry("CVE-2024-1", severity="HIGH"),
            _entry("CVE-2024-2", severity="LOW"),
        ], f)

    delta = tmp_path / "delta.json"
    with open(delta, "w") as f:
        json.dump([
            _entry("CVE-2024-1", severity="CRITICAL"),  # updated
            _entry("CVE-2024-3", severity="MEDIUM"),    # new
        ], f)

    inserted, updated = merge_nvd_json(cumulative, delta)

    assert inserted == ["CVE-2024-3"]
    assert updated == ["CVE-2024-1"]

    merged = _read(cumulative)
    assert len(merged) == 3
    by_id = {item["cve"]["id"]: item for item in merged}
    assert by_id["CVE-2024-1"]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] == "CRITICAL"
    assert by_id["CVE-2024-2"]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] == "LOW"


def test_merge_skips_entries_without_cve_id(tmp_path):
    cumulative = tmp_path / "nvd_cves.json"
    delta = tmp_path / "delta.json"
    with open(delta, "w") as f:
        json.dump([_entry("CVE-2024-1"), {"cve": {}}, {}], f)

    inserted, updated = merge_nvd_json(cumulative, delta)

    assert inserted == ["CVE-2024-1"]
    assert updated == []
    assert len(_read(cumulative)) == 1


def test_merge_is_idempotent_on_same_delta(tmp_path):
    cumulative = tmp_path / "nvd_cves.json"
    delta = tmp_path / "delta.json"
    with open(delta, "w") as f:
        json.dump([_entry("CVE-2024-1")], f)

    merge_nvd_json(cumulative, delta)
    inserted, updated = merge_nvd_json(cumulative, delta)

    # Re-applying same delta: already there → updated, no new inserts
    assert inserted == []
    assert updated == ["CVE-2024-1"]
    assert len(_read(cumulative)) == 1


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
