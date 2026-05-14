"""TTL cache for GitHub commit metadata.

The enrichment phase fetches per-commit data (author, files, stats,
comments) via the GitHub API — the single most expensive step in the
weekly pipeline. This module caches each fetch on disk so subsequent runs
reuse it instead of re-hitting the rate-limited API.

Layout:
    data/github_cache/<xx>/<sha>.json

The two-char shard keeps any single directory from growing past ~1k files.
Each cached entry carries its own `fetched_at` timestamp so entries
expire per-row (not globally), which matters when commits are added to the
cache across many runs.

TTL default: 30 days. Override with env var GITHUB_CACHE_TTL_DAYS.
Force-pushes that rewrite SHAs are undetectable without a fresh fetch, so
the TTL is the only correctness bound — keep it modest.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_TTL_DAYS = 30
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def get_cache_ttl_days() -> int:
    """TTL for cached entries. Env override: GITHUB_CACHE_TTL_DAYS."""
    raw = os.environ.get("GITHUB_CACHE_TTL_DAYS")
    if raw:
        try:
            return int(raw)
        except ValueError:
            log.warning(
                "Invalid GITHUB_CACHE_TTL_DAYS=%r, falling back to %d",
                raw, DEFAULT_TTL_DAYS,
            )
    return DEFAULT_TTL_DAYS


@dataclass
class CacheStats:
    """Per-run cache effectiveness: how many commits came from disk vs API."""

    hits: int = 0
    misses: int = 0
    expired: int = 0
    writes: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses + self.expired

    def summary(self) -> str:
        total = max(self.lookups, 1)
        rate = 100 * self.hits / total
        return (
            f"hits={self.hits} misses={self.misses} expired={self.expired} "
            f"writes={self.writes} ({rate:.1f}% hit rate)"
        )


class GithubCache:
    """Disk-backed TTL cache keyed by commit SHA."""

    def __init__(self, cache_dir: str | Path, ttl_days: int | None = None):
        self.cache_dir = Path(cache_dir)
        self.ttl_days = ttl_days if ttl_days is not None else get_cache_ttl_days()
        self.stats = CacheStats()

    def _path_for(self, sha: str) -> Path:
        sha = sha.lower().strip()
        if not _SHA_RE.match(sha):
            raise ValueError(f"Invalid commit SHA: {sha!r}")
        return self.cache_dir / sha[:2] / f"{sha}.json"

    def get(self, sha: str) -> dict | None:
        """Return cached data for sha, or None if missing/expired."""
        path = self._path_for(sha)
        if not path.exists():
            self.stats.misses += 1
            return None
        try:
            with open(path) as f:
                entry = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Treat corrupt cache entries as misses; they'll be overwritten.
            self.stats.misses += 1
            return None

        fetched_at = entry.get("fetched_at")
        if not fetched_at:
            self.stats.expired += 1
            return None
        try:
            ts = datetime.fromisoformat(fetched_at)
        except ValueError:
            self.stats.expired += 1
            return None

        if datetime.now(timezone.utc) - ts > timedelta(days=self.ttl_days):
            self.stats.expired += 1
            return None

        self.stats.hits += 1
        return entry.get("data")

    def put(self, sha: str, data: dict) -> None:
        """Store data for sha with the current timestamp."""
        path = self._path_for(sha)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w") as f:
            json.dump(entry, f)
        tmp.replace(path)
        self.stats.writes += 1

    def invalidate(self, sha: str) -> bool:
        """Remove a cache entry if it exists. Returns True if removed."""
        path = self._path_for(sha)
        if path.exists():
            path.unlink()
            return True
        return False


def extract_commit_data(commit) -> dict:
    """Convert a PyGithub Commit object into a plain serializable dict.

    Kept separate from the cache so the cache stays framework-agnostic and
    testable without a GitHub client.
    """
    c = commit.commit
    files = []
    for f in commit.files or []:
        files.append({
            "filename": f.filename,
            "additions": int(f.additions),
            "deletions": int(f.deletions),
            "changes": int(f.changes),
            "status": f.status,
            "previous_filename": getattr(f, "previous_filename", None),
            "patch": f.patch.strip() if f.patch else None,
        })

    comments = []
    for cm in commit.get_comments():
        comments.append({
            "author": cm.user.login if cm.user else None,
            "date": cm.created_at.isoformat() + "Z" if cm.created_at else None,
            "body": cm.body.strip() if cm.body else "",
        })

    verification = getattr(c, "verification", None)

    return {
        "sha": commit.sha,
        "message": c.message.strip() if c.message else "",
        "author_name": c.author.name.strip() if c.author and c.author.name else None,
        "author_date": c.author.date.isoformat() + "Z" if c.author and c.author.date else None,
        "committer_name": c.committer.name.strip() if c.committer and c.committer.name else None,
        "committer_date": c.committer.date.isoformat() + "Z" if c.committer and c.committer.date else None,
        "is_signed": bool(verification.verified) if verification else False,
        "parents": [p.sha for p in c.parents],
        "additions": int(commit.stats.additions),
        "deletions": int(commit.stats.deletions),
        "files_changed": int(commit.stats.total),
        "comments": comments,
        "files": files,
    }
