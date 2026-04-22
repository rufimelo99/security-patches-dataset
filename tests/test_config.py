"""Tests for scripts/lib/config.py lookback helpers.

Run with: python -m pytest tests/test_config.py
Or standalone: python tests/test_config.py
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lib import config  # noqa: E402


def _setup(tmp_path: Path, monkeypatch_env: dict | None = None):
    """Redirect STATE_FILE into tmp_path and clear env overrides."""
    config.STATE_FILE = tmp_path / ".pipeline_state.json"
    for k in ("PIPELINE_LOOKBACK_DAYS",):
        os.environ.pop(k, None)
    if monkeypatch_env:
        for k, v in monkeypatch_env.items():
            os.environ[k] = v


def test_lookback_days_default(tmp_path):
    _setup(tmp_path)
    assert config.get_lookback_days() == 14


def test_lookback_days_env_override(tmp_path):
    _setup(tmp_path, {"PIPELINE_LOOKBACK_DAYS": "30"})
    assert config.get_lookback_days() == 30


def test_lookback_days_invalid_env_falls_back(tmp_path):
    _setup(tmp_path, {"PIPELINE_LOOKBACK_DAYS": "abc"})
    assert config.get_lookback_days() == 14


def test_lookback_start_none_when_never_run(tmp_path):
    _setup(tmp_path)
    assert config.get_lookback_start("collect_nvd") is None


def test_lookback_start_subtracts_window(tmp_path):
    _setup(tmp_path)
    now = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
    config.save_pipeline_state({"collect_nvd_last_run": now.isoformat()})

    start = config.get_lookback_start("collect_nvd")
    parsed = datetime.fromisoformat(start)
    assert parsed == now - timedelta(days=14)


def test_lookback_start_respects_custom_window(tmp_path):
    _setup(tmp_path)
    now = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
    config.save_pipeline_state({"collect_nvd_last_run": now.isoformat()})

    start = config.get_lookback_start("collect_nvd", lookback_days=7)
    parsed = datetime.fromisoformat(start)
    assert parsed == now - timedelta(days=7)


def test_lookback_start_respects_env_override(tmp_path):
    _setup(tmp_path, {"PIPELINE_LOOKBACK_DAYS": "30"})
    now = datetime(2026, 4, 15, 10, 0, 0, tzinfo=timezone.utc)
    config.save_pipeline_state({"collect_nvd_last_run": now.isoformat()})

    start = config.get_lookback_start("collect_nvd")
    parsed = datetime.fromisoformat(start)
    assert parsed == now - timedelta(days=30)


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
