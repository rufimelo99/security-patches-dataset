"""Upsert CSV files by key columns, reporting new vs updated rows.

Used by the incremental pipeline to merge weekly deltas into cumulative tables
without rebuilding from scratch. Classifies every delta row as one of:

- inserted: key not present in target.
- updated:  key present, but at least one compare column differs.
- unchanged: key present, all compare columns equal.

The result object exposes the actual key values for each category so callers
can log exactly which vulnerabilities/commits are new vs. revised.
"""
from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import pandas as pd

log = logging.getLogger(__name__)


@dataclass
class UpsertResult:
    """Outcome of an upsert/replace: lists of affected key tuples."""

    table: str
    key_cols: list[str]
    inserted: list[tuple] = field(default_factory=list)
    updated: list[tuple] = field(default_factory=list)
    removed: list[tuple] = field(default_factory=list)
    unchanged: int = 0

    @property
    def n_inserted(self) -> int:
        return len(self.inserted)

    @property
    def n_updated(self) -> int:
        return len(self.updated)

    @property
    def n_removed(self) -> int:
        return len(self.removed)

    @property
    def n_changed(self) -> int:
        return self.n_inserted + self.n_updated + self.n_removed

    def summary(self) -> str:
        base = (
            f"{self.table}: inserted={self.n_inserted} "
            f"updated={self.n_updated} unchanged={self.unchanged}"
        )
        if self.removed:
            base += f" removed={self.n_removed}"
        return base

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "key_cols": self.key_cols,
            "inserted": [list(k) for k in self.inserted],
            "updated": [list(k) for k in self.updated],
            "removed": [list(k) for k in self.removed],
            "unchanged_count": self.unchanged,
        }


def _read_csv_or_empty(path: Path, columns: Sequence[str]) -> pd.DataFrame:
    if path.exists() and path.stat().st_size > 0:
        return pd.read_csv(path, escapechar="\\", dtype=str, keep_default_na=False)
    return pd.DataFrame(columns=list(columns))


def _normalize_strings(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for c in out.columns:
        out[c] = out[c].astype(str)
        # Treat literal "nan" (from NaN float coercion) as empty.
        out.loc[out[c] == "nan", c] = ""
    return out


def _align_columns(
    target: pd.DataFrame, delta: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Union columns, fill missing with empty string on both sides."""
    all_cols = list(dict.fromkeys(list(target.columns) + list(delta.columns)))
    for c in all_cols:
        if c not in target.columns:
            target[c] = ""
        if c not in delta.columns:
            delta[c] = ""
    return target[all_cols], delta[all_cols], all_cols


def upsert_csv(
    target_path: str | Path,
    delta_df: pd.DataFrame,
    key_cols: Sequence[str],
    compare_cols: Sequence[str] | None = None,
    table_name: str | None = None,
) -> UpsertResult:
    """Merge delta_df into target CSV by key_cols, writing atomically.

    Args:
        target_path: CSV path to update (created if missing).
        delta_df: incoming rows (the "new" data from this run's window).
        key_cols: columns that uniquely identify a row.
        compare_cols: columns to compare for change detection.
            Defaults to every non-key column.
        table_name: friendly name for logging (defaults to file stem).

    Returns:
        UpsertResult listing which keys were inserted vs updated vs unchanged.
    """
    target_path = Path(target_path)
    key_cols = list(key_cols)
    name = table_name or target_path.stem

    target = _read_csv_or_empty(target_path, delta_df.columns)
    delta = _normalize_strings(delta_df)
    target, delta, all_cols = _align_columns(target, delta)

    missing_keys = [k for k in key_cols if k not in all_cols]
    if missing_keys:
        raise ValueError(f"key_cols missing from data: {missing_keys}")

    if compare_cols is None:
        compare_cols = [c for c in all_cols if c not in key_cols]
    else:
        compare_cols = list(compare_cols)

    # Categorize delta rows via a left-join on keys.
    check = delta.merge(
        target[key_cols + compare_cols],
        on=key_cols,
        how="left",
        indicator=True,
        suffixes=("", "__target"),
    )

    is_new = check["_merge"] == "left_only"
    is_existing = check["_merge"] == "both"

    change_mask = pd.Series(False, index=check.index)
    for c in compare_cols:
        tgt_col = f"{c}__target"
        if tgt_col in check.columns:
            change_mask |= check[c].fillna("") != check[tgt_col].fillna("")

    updated_mask = is_existing & change_mask
    unchanged_mask = is_existing & ~change_mask

    inserted = [
        tuple(r) for r in check.loc[is_new, key_cols].itertuples(index=False, name=None)
    ]
    updated = [
        tuple(r) for r in check.loc[updated_mask, key_cols].itertuples(index=False, name=None)
    ]
    unchanged = int(unchanged_mask.sum())

    # Rebuild: keep target rows whose key is not in delta, then append delta.
    delta_keys = delta[key_cols].drop_duplicates()
    target_keep = target.merge(delta_keys, on=key_cols, how="left", indicator=True)
    target_keep = target_keep[target_keep["_merge"] == "left_only"].drop(columns=["_merge"])

    merged = pd.concat([target_keep, delta], ignore_index=True)

    # Atomic write.
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = target_path.with_suffix(target_path.suffix + ".tmp")
    merged.to_csv(
        tmp,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )
    tmp.replace(target_path)

    result = UpsertResult(
        table=name,
        key_cols=key_cols,
        inserted=inserted,
        updated=updated,
        unchanged=unchanged,
    )
    log.info(
        "Upsert %s: inserted=%d updated=%d unchanged=%d",
        name,
        result.n_inserted,
        result.n_updated,
        result.unchanged,
    )
    return result


def replace_csv(
    target_path: str | Path,
    new_df: pd.DataFrame,
    key_cols: Sequence[str],
    compare_cols: Sequence[str] | None = None,
    table_name: str | None = None,
) -> UpsertResult:
    """Replace target CSV with new_df, classifying every key transition.

    Use this (not `upsert_csv`) when the caller has the full authoritative
    state — rows present in target but absent from new_df are removed.

    Returns an UpsertResult with `inserted`, `updated`, `removed`, and
    `unchanged`, so callers can log exactly which vuln_ids appeared,
    changed, or disappeared this run.
    """
    target_path = Path(target_path)
    key_cols = list(key_cols)
    name = table_name or target_path.stem

    target = _read_csv_or_empty(target_path, new_df.columns)
    new = _normalize_strings(new_df)
    target, new, all_cols = _align_columns(target, new)

    missing_keys = [k for k in key_cols if k not in all_cols]
    if missing_keys:
        raise ValueError(f"key_cols missing from data: {missing_keys}")

    if compare_cols is None:
        compare_cols = [c for c in all_cols if c not in key_cols]
    else:
        compare_cols = list(compare_cols)

    check = new.merge(
        target[key_cols + compare_cols],
        on=key_cols,
        how="outer",
        indicator=True,
        suffixes=("", "__target"),
    )

    is_new = check["_merge"] == "left_only"
    is_gone = check["_merge"] == "right_only"
    is_both = check["_merge"] == "both"

    change_mask = pd.Series(False, index=check.index)
    for c in compare_cols:
        tgt_col = f"{c}__target"
        if tgt_col in check.columns:
            change_mask |= check[c].fillna("") != check[tgt_col].fillna("")

    inserted = [
        tuple(r) for r in check.loc[is_new, key_cols].itertuples(index=False, name=None)
    ]
    updated = [
        tuple(r) for r in check.loc[is_both & change_mask, key_cols].itertuples(index=False, name=None)
    ]
    removed = [
        tuple(r) for r in check.loc[is_gone, key_cols].itertuples(index=False, name=None)
    ]
    unchanged = int((is_both & ~change_mask).sum())

    # Write the new state atomically (full replacement).
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = target_path.with_suffix(target_path.suffix + ".tmp")
    new.to_csv(
        tmp,
        quoting=csv.QUOTE_NONNUMERIC,
        escapechar="\\",
        doublequote=False,
        index=False,
    )
    tmp.replace(target_path)

    result = UpsertResult(
        table=name,
        key_cols=key_cols,
        inserted=inserted,
        updated=updated,
        removed=removed,
        unchanged=unchanged,
    )
    log.info(
        "Replace %s: inserted=%d updated=%d removed=%d unchanged=%d",
        name, result.n_inserted, result.n_updated, result.n_removed, result.unchanged,
    )
    return result


def write_changelog(
    log_dir: str | Path,
    phase: str,
    results: Sequence[UpsertResult],
    run_id: str | None = None,
) -> Path:
    """Append a per-run changelog entry for the given upsert results.

    Produces data/.pipeline_changes.jsonl where each line is one phase's
    summary — useful to answer "what changed this week?" without diffing CSVs.
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / ".pipeline_changes.jsonl"

    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    entry = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "tables": [r.to_dict() for r in results],
    }
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return path
