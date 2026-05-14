"""End-to-end integration test for the enrich fetch path.

Mocks the GitHub Repository to verify:
  1. O(n squared) is gone: get_commit is called once per unique SHA.
  2. Cross-run cache: a second run with the same input and same cache dir
     makes zero API calls.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import pandas as pd  # noqa: E402

import github_data  # noqa: E402
from lib.github_cache import GithubCache  # noqa: E402


def _fake_commit(sha: str):
    c = MagicMock()
    c.sha = sha
    c.commit.sha = sha
    c.commit.message = f"msg {sha[:6]}"
    c.commit.author.name = "Alice"
    c.commit.author.date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.commit.committer.name = "Alice"
    c.commit.committer.date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    c.commit.parents = []
    c.commit.verification = SimpleNamespace(verified=False)
    c.stats.additions = 1
    c.stats.deletions = 0
    c.stats.total = 1
    c.files = []
    c.get_comments.return_value = []
    return c


def _fake_repo():
    repo = MagicMock()
    repo.get_commit.side_effect = lambda sha: _fake_commit(sha)
    return repo


def test_no_redundant_api_calls_across_rows_of_same_chain(tmp_path):
    """Vuln with chain of 3 commits = 3 rows. Without the fix, sort_chain
    would fetch each commit 3 times (9 calls). After the fix: 3 calls total."""
    shas = ["a" * 40, "b" * 40, "c" * 40]
    chain = {f"https://github.com/owner/repo/commit/{s}" for s in shas}

    df = pd.DataFrame([
        {"vuln_id": "V1", "project": "https://github.com/owner/repo",
         "commit_sha": s, "chain": chain, "files": None, "message": None}
        for s in shas
    ])

    repo = _fake_repo()
    git = MagicMock()
    git.get_repo.return_value = repo
    cache = GithubCache(tmp_path)
    sha_cache = {}

    github_data.metadata(
        "https://github.com/owner/repo", df, git, [],
        cache=cache, sha_cache=sha_cache,
    )

    assert repo.get_commit.call_count == 3, (
        f"expected 3 unique fetches, got {repo.get_commit.call_count}"
    )


def test_second_run_is_zero_api_calls(tmp_path):
    """Persisted disk cache from run 1 makes run 2 hit zero API."""
    shas = ["a" * 40, "b" * 40]
    chain = {f"https://github.com/owner/repo/commit/{s}" for s in shas}

    def make_df():
        return pd.DataFrame([
            {"vuln_id": "V1", "project": "https://github.com/owner/repo",
             "commit_sha": s, "chain": chain, "files": None, "message": None}
            for s in shas
        ])

    cache = GithubCache(tmp_path)

    repo1 = _fake_repo()
    git1 = MagicMock(); git1.get_repo.return_value = repo1
    github_data.metadata(
        "https://github.com/owner/repo", make_df(), git1, [],
        cache=cache, sha_cache={},
    )
    assert repo1.get_commit.call_count == 2

    repo2 = _fake_repo()
    git2 = MagicMock(); git2.get_repo.return_value = repo2
    github_data.metadata(
        "https://github.com/owner/repo", make_df(), git2, [],
        cache=cache, sha_cache={},
    )
    assert repo2.get_commit.call_count == 0, "second run should hit 0 API"
