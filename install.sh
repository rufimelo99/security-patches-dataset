#!/usr/bin/env bash
set -euo pipefail

# Name of the conda environment to create or update
ENV_NAME="sec-patches"
PYTHON_VERSION="3.12.2"  # Choose a Python version you prefer

# -------------------------------------------------------
# 1) Create the environment with a base Python version
# -------------------------------------------------------
conda create -n "$ENV_NAME" python="$PYTHON_VERSION" -y

# This enables the "conda activate" command below
# (necessary in a non-interactive script).
# Some systems may need slightly different ways of sourcing.
source "$(conda info --base)/etc/profile.d/conda.sh"

# Activate the environment
conda activate "$ENV_NAME"

# -------------------------------------------------------
# 2) Read requirements.txt line-by-line
#    - Attempt conda install
#    - If not found, install via pip
# -------------------------------------------------------
REQ_FILE="requirements.txt"

# Make sure the file exists
if [[ ! -f "$REQ_FILE" ]]; then
  echo "ERROR: '$REQ_FILE' not found!"
  exit 1
fi

while IFS= read -r requirement; do
  # Skip empty lines or comment lines
  if [[ -z "$requirement" || "$requirement" =~ ^# ]]; then
    continue
  fi

  # We'll attempt 'conda search' on the "raw" requirement line.
  # For example, if the line is 'pandas==1.4.0', we just check 'pandas'.
  # This extraction is simplistic—improvement may be needed if you have
  # more complex version specs or extras (like 'package[extra]==1.0').
  base_pkg_name=$(echo "$requirement" | sed 's/[=<>!].*//')

  # Check if available via conda-forge or default channels
  if conda search -c conda-forge "$base_pkg_name" >/dev/null 2>&1; then
    echo "Installing '$requirement' with conda..."
    conda install -c conda-forge -y "$requirement"
  else
    echo "Installing '$requirement' with pip..."
    pip install "$requirement"
  fi
done < "$REQ_FILE"

echo "--------------------------------------"
echo "Installation complete in environment: $ENV_NAME"
echo "To use this environment, run:"
echo "  conda activate $ENV_NAME"