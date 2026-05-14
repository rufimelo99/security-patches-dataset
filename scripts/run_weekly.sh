#!/usr/bin/env bash
# Weekly incremental pipeline runner for the GCP VM.
#
# Designed to be invoked from cron. Guarantees:
#   - Only one run at a time (flock on a lock file).
#   - Output goes to a timestamped log so old runs stay inspectable.
#   - Non-zero exit on failure so cron emails / monitoring catch it.
#
# Pick up the latest dataset from your PC with:
#   gcloud compute scp --recurse VM_NAME:/path/to/security-patches-dataset/dataset ./
#
# Or sync via GCS if you prefer:
#   gsutil -m rsync -d -r dataset gs://YOUR_BUCKET/dataset
set -euo pipefail

# Resolve repo root from this script's location so cron's cwd doesn't matter.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOG_DIR="${REPO_ROOT}/logs"
LOCK_FILE="${REPO_ROOT}/.pipeline.lock"
PYTHON="${PYTHON:-python3}"

mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/pipeline-$(date -u +%Y%m%dT%H%M%SZ).log"

# flock returns 1 if another run still holds the lock → exit quietly.
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
    echo "Another pipeline run is in progress — skipping." >&2
    exit 0
fi

cd "${REPO_ROOT}"
echo "=== Pipeline run started $(date -u) ===" | tee -a "${LOG_FILE}"
"${PYTHON}" scripts/pipeline.py run >> "${LOG_FILE}" 2>&1
echo "=== Pipeline run finished $(date -u) ===" | tee -a "${LOG_FILE}"

# Keep only the last 8 run logs (~2 months at weekly cadence).
ls -1t "${LOG_DIR}"/pipeline-*.log 2>/dev/null | tail -n +9 | xargs -r rm --
