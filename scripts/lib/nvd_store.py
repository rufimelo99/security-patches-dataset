"""Cumulative storage for raw NVD JSON.

NVD's API returns a flat list of vulnerability objects. For incremental
updates we need to keep a single on-disk corpus that earlier CVEs are still
in, merging each week's delta in by CVE ID.

This module owns the merge logic so `build_tables.py` can keep reading a
single authoritative `nvd_cves.json` without knowing it was built across
multiple runs.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def _cve_id(item):
    return item.get("cve", {}).get("id")


def merge_nvd_json(cumulative_path, delta_path):
    """Merge delta NVD JSON into the cumulative file, keyed by CVE ID.

    Delta entries overwrite cumulative ones (so late-edit fields like CVSS
    re-scoring or newly added references land correctly).

    Args:
        cumulative_path: existing cumulative JSON (created if missing).
        delta_path: JSON produced by a delta download run.

    Returns:
        (inserted_ids, updated_ids) — lists of CVE IDs for changelog use.
    """
    cumulative_path = Path(cumulative_path)
    delta_path = Path(delta_path)

    if cumulative_path.exists() and cumulative_path.stat().st_size > 0:
        with open(cumulative_path) as f:
            cumulative = json.load(f)
    else:
        cumulative = []

    index = {}
    for i, item in enumerate(cumulative):
        cid = _cve_id(item)
        if cid:
            index[cid] = i

    with open(delta_path) as f:
        delta = json.load(f)

    inserted = []
    updated = []
    for item in delta:
        cid = _cve_id(item)
        if not cid:
            continue
        if cid in index:
            cumulative[index[cid]] = item
            updated.append(cid)
        else:
            index[cid] = len(cumulative)
            cumulative.append(item)
            inserted.append(cid)

    # Atomic write.
    cumulative_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = cumulative_path.with_suffix(cumulative_path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(cumulative, f)
    tmp.replace(cumulative_path)

    log.info(
        "NVD JSON merge: inserted=%d updated=%d total=%d",
        len(inserted), len(updated), len(cumulative),
    )
    return inserted, updated
