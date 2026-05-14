"""Tests for scripts/lib/github_cache.GithubCache.

Run with: python -m pytest tests/test_github_cache.py
Or standalone: python tests/test_github_cache.py
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lib import github_cache  # noqa: E402
from lib.github_cache import GithubCache, get_cache_ttl_days  # noqa: E402


SHA = "abc123def456"


def test_ttl_default(tmp_path):
    os.environ.pop("GITHUB_CACHE_TTL_DAYS", None)
    assert get_cache_ttl_days() == 30


def test_ttl_env_override(tmp_path):
    os.environ["GITHUB_CACHE_TTL_DAYS"] = "7"
    try:
        assert get_cache_ttl_days() == 7
    finally:
        os.environ.pop("GITHUB_CACHE_TTL_DAYS", None)


def test_ttl_invalid_env_falls_back(tmp_path):
    os.environ["GITHUB_CACHE_TTL_DAYS"] = "abc"
    try:
        assert get_cache_ttl_days() == 30
    finally:
        os.environ.pop("GITHUB_CACHE_TTL_DAYS", None)


def test_miss_returns_none(tmp_path):
    cache = GithubCache(tmp_path)
    assert cache.get(SHA) is None
    assert cache.stats.misses == 1
    assert cache.stats.hits == 0


def test_put_and_get_roundtrip(tmp_path):
    cache = GithubCache(tmp_path)
    data = {"message": "fix", "additions": 3}
    cache.put(SHA, data)
    assert cache.get(SHA) == data
    assert cache.stats.hits == 1
    assert cache.stats.writes == 1


def test_sharded_path_layout(tmp_path):
    cache = GithubCache(tmp_path)
    cache.put(SHA, {"x": 1})
    assert (tmp_path / "ab" / f"{SHA}.json").exists()


def test_expired_entry_returns_none(tmp_path):
    cache = GithubCache(tmp_path, ttl_days=7)
    cache.put(SHA, {"x": 1})

    # Backdate the entry to 10 days ago
    path = cache._path_for(SHA)
    with open(path) as f:
        entry = json.load(f)
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    entry["fetched_at"] = old
    with open(path, "w") as f:
        json.dump(entry, f)

    assert cache.get(SHA) is None
    assert cache.stats.expired == 1


def test_corrupt_entry_treated_as_miss(tmp_path):
    cache = GithubCache(tmp_path)
    path = cache._path_for(SHA)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not valid json")
    assert cache.get(SHA) is None
    assert cache.stats.misses == 1


def test_missing_fetched_at_treated_as_expired(tmp_path):
    cache = GithubCache(tmp_path)
    path = cache._path_for(SHA)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"data": {"x": 1}}, f)
    assert cache.get(SHA) is None
    assert cache.stats.expired == 1


def test_invalidate_removes_entry(tmp_path):
    cache = GithubCache(tmp_path)
    cache.put(SHA, {"x": 1})
    assert cache.invalidate(SHA) is True
    assert cache.invalidate(SHA) is False
    assert cache.get(SHA) is None


def test_rejects_invalid_sha(tmp_path):
    cache = GithubCache(tmp_path)

    for bad in ("not-a-sha", "", "XYZ"):
        try:
            cache.get(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for sha={bad!r}")


def test_put_is_atomic(tmp_path):
    cache = GithubCache(tmp_path)
    cache.put(SHA, {"x": 1})
    # No .tmp leftover after successful write
    assert not (tmp_path / "ab" / f"{SHA}.json.tmp").exists()


def test_stats_hit_rate_summary(tmp_path):
    cache = GithubCache(tmp_path)
    cache.put(SHA, {"x": 1})
    cache.get(SHA)         # hit
    cache.get("fff000aaa") # miss
    s = cache.stats.summary()
    assert "hits=1" in s
    assert "misses=1" in s
    assert "writes=1" in s


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
