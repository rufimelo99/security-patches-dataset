"""3-layer commit fetch (in-memory, disk cache, GitHub API) + CachedCommit shim.

The enrichment phase fetches per-commit data via PyGithub. Repeated access to the
same SHA within a run (O(n squared) bug in github_data.py) and between runs (no
persistent cache) is the main reason the pipeline is slow. This module unifies
both caches so github_data.py only calls a single function per SHA.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from github import RateLimitExceededException

from lib.github_cache import GithubCache, extract_commit_data


def _parse_iso(s):
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


class _CachedComment:
    __slots__ = ("user", "created_at", "body")

    def __init__(self, d):
        self.user = SimpleNamespace(login=d.get("author"))
        self.created_at = _parse_iso(d.get("date"))
        self.body = d.get("body", "")


class _CachedFile:
    __slots__ = ("filename", "additions", "deletions", "changes",
                 "status", "previous_filename", "patch")

    def __init__(self, d):
        self.filename = d["filename"]
        self.additions = d["additions"]
        self.deletions = d["deletions"]
        self.changes = d["changes"]
        self.status = d["status"]
        self.previous_filename = d.get("previous_filename")
        self.patch = d.get("patch")


class CachedCommit:
    """Expose the PyGithub Commit interface over a cached dict."""

    def __init__(self, data):
        self._comments = [_CachedComment(c) for c in data.get("comments", [])]
        self._files = [_CachedFile(f) for f in data.get("files", [])]

        self.sha = data["sha"]
        self.files = self._files
        self.stats = SimpleNamespace(
            additions=data.get("additions", 0),
            deletions=data.get("deletions", 0),
            total=data.get("files_changed", 0),
        )
        self.commit = SimpleNamespace(
            sha=data["sha"],
            message=data.get("message", ""),
            author=SimpleNamespace(
                name=data.get("author_name"),
                date=_parse_iso(data.get("author_date")),
            ),
            committer=SimpleNamespace(
                name=data.get("committer_name"),
                date=_parse_iso(data.get("committer_date")),
            ),
            parents=[SimpleNamespace(sha=p) for p in data.get("parents", [])],
            verification=SimpleNamespace(verified=bool(data.get("is_signed", False))),
        )

    def get_comments(self):
        return self._comments
