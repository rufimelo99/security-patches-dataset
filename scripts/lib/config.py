"""Unified configuration for the security-patches pipeline."""
import json
import os
import time
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta

from github import Github

# Lookback window for incremental updates.
# Covers retroactive edits (CVEs re-scored, new references added) made after
# their initial publication. Override with env var PIPELINE_LOOKBACK_DAYS.
DEFAULT_LOOKBACK_DAYS = 14

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "scripts" / "config"
STATE_FILE = PROJECT_ROOT / "data" / ".pipeline_state.json"


def load_github_tokens(config_path=None):
    """Load GitHub tokens from config file. Returns list of token dicts."""
    if config_path is None:
        config_path = CONFIG_DIR / "github.json"
    with open(config_path) as f:
        data = json.load(f)
    # Support both single-token and multi-token configs
    if isinstance(data, list):
        return data
    return [data]


def get_github_client(tokens):
    """Get a GitHub client with available rate limit. Rotates through tokens."""
    for token in tokens:
        client = Github(token["github_token"])
        remaining = client.rate_limiting[0]
        if remaining > 0:
            log.info("Using token with %d requests remaining", remaining)
            return client
    log.warning("All tokens exhausted. Waiting 60s before retry...")
    time.sleep(60)
    return get_github_client(tokens)


def load_pipeline_state():
    """Load pipeline state (last run timestamps, etc.)."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_pipeline_state(state):
    """Save pipeline state."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def update_phase_timestamp(phase_name):
    """Record when a pipeline phase last completed."""
    state = load_pipeline_state()
    state[f"{phase_name}_last_run"] = datetime.now(timezone.utc).isoformat()
    save_pipeline_state(state)


def get_phase_timestamp(phase_name):
    """Get the last run timestamp for a pipeline phase."""
    state = load_pipeline_state()
    return state.get(f"{phase_name}_last_run")


def get_lookback_days():
    """Lookback window for incremental updates. Env: PIPELINE_LOOKBACK_DAYS."""
    raw = os.environ.get("PIPELINE_LOOKBACK_DAYS")
    if raw:
        try:
            return int(raw)
        except ValueError:
            log.warning(
                "Invalid PIPELINE_LOOKBACK_DAYS=%r, falling back to %d",
                raw, DEFAULT_LOOKBACK_DAYS,
            )
    return DEFAULT_LOOKBACK_DAYS


def get_lookback_start(phase_name, lookback_days=None):
    """Return ISO datetime for the 'modified since' filter of a phase.

    Equals (last_run - lookback_days), so records revised shortly after their
    initial publication are re-fetched in the next run.

    Returns None if the phase has never run — callers should treat this as
    a signal to perform a full refresh (first-time bootstrap).
    """
    last_run = get_phase_timestamp(phase_name)
    if not last_run:
        return None
    if lookback_days is None:
        lookback_days = get_lookback_days()
    dt = datetime.fromisoformat(last_run)
    return (dt - timedelta(days=lookback_days)).isoformat()
