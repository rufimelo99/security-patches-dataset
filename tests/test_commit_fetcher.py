"""Tests for scripts/lib/commit_fetcher."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from lib.commit_fetcher import CachedCommit  # noqa: E402


SAMPLE_DATA = {
    "sha": "abc123def456abc123def456abc123def456abcd",
    "message": "fix: patch the thing",
    "author_name": "Alice",
    "author_date": "2024-01-15T10:30:00Z",
    "committer_name": "Bob",
    "committer_date": "2024-01-15T10:35:00Z",
    "is_signed": True,
    "parents": ["p1" * 20, "p2" * 20],
    "additions": 10,
    "deletions": 2,
    "files_changed": 3,
    "comments": [
        {"author": "reviewer1", "date": "2024-01-16T09:00:00Z", "body": "lgtm"},
    ],
    "files": [
        {
            "filename": "src/a.py",
            "additions": 5, "deletions": 1, "changes": 6,
            "status": "modified",
            "previous_filename": None,
            "patch": "@@ ...",
        },
    ],
}


def test_cached_commit_exposes_sha_and_stats():
    c = CachedCommit(SAMPLE_DATA)
    assert c.sha == SAMPLE_DATA["sha"]
    assert c.commit.sha == SAMPLE_DATA["sha"]
    assert c.stats.additions == 10
    assert c.stats.deletions == 2
    assert c.stats.total == 3


def test_cached_commit_exposes_author_and_committer():
    c = CachedCommit(SAMPLE_DATA)
    assert c.commit.author.name == "Alice"
    assert c.commit.author.date.year == 2024
    assert c.commit.author.date.hour == 10
    assert c.commit.author.date.tzinfo is not None
    assert c.commit.committer.name == "Bob"


def test_cached_commit_exposes_parents_as_objects_with_sha():
    c = CachedCommit(SAMPLE_DATA)
    assert len(c.commit.parents) == 2
    assert c.commit.parents[0].sha == "p1" * 20


def test_cached_commit_verification_verified_is_bool():
    c = CachedCommit(SAMPLE_DATA)
    assert c.commit.verification.verified is True


def test_cached_commit_files_iterable_with_fields():
    c = CachedCommit(SAMPLE_DATA)
    files = list(c.files)
    assert len(files) == 1
    f = files[0]
    assert f.filename == "src/a.py"
    assert f.additions == 5
    assert f.status == "modified"
    assert f.previous_filename is None


def test_cached_commit_get_comments_returns_pygithub_like_objects():
    c = CachedCommit(SAMPLE_DATA)
    comments = list(c.get_comments())
    assert len(comments) == 1
    cm = comments[0]
    assert cm.user.login == "reviewer1"
    assert cm.body == "lgtm"
    assert cm.created_at.isoformat().startswith("2024-01-16T09:00:00")


def test_cached_commit_empty_comments_and_files():
    data = {**SAMPLE_DATA, "comments": [], "files": []}
    c = CachedCommit(data)
    assert list(c.get_comments()) == []
    assert list(c.files) == []


from unittest.mock import MagicMock

from lib.commit_fetcher import fetch_commit


def test_fetch_commit_returns_memoized_value_without_api_call():
    repo = MagicMock()
    sha_cache = {}
    cache = None

    sentinel = object()
    sha_cache["deadbeef" * 5] = sentinel

    result = fetch_commit(
        repo, "deadbeef" * 5, git=MagicMock(), config=[],
        cache=cache, sha_cache=sha_cache,
    )
    assert result is sentinel
    repo.get_commit.assert_not_called()


def test_fetch_commit_disk_hit_populates_memory(tmp_path):
    from lib.github_cache import GithubCache
    cache = GithubCache(tmp_path)
    sha = "a" * 40
    cache.put(sha, {**SAMPLE_DATA, "sha": sha})

    repo = MagicMock()
    sha_cache = {}

    result = fetch_commit(
        repo, sha, git=MagicMock(), config=[],
        cache=cache, sha_cache=sha_cache,
    )

    assert result.sha == sha
    assert sha in sha_cache
    assert sha_cache[sha] is result
    repo.get_commit.assert_not_called()
