#!/usr/bin/env bash
set -euo pipefail

# Get absolute path to your project root
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Define where the Remill submodule lives
REMILL_DIR="${REPO_DIR}/external/remill"

echo "[+] Building Remill..."

DOWNLOAD_DIR="${REPO_DIR}/downloads/lifting-bits-downloads"
BUILD_DIR="${REPO_DIR}/build/remill-build"

mkdir -p "${DOWNLOAD_DIR}" "${BUILD_DIR}"

"${REMILL_DIR}/scripts/build.sh" --prefix "/" --build-dir "${BUILD_DIR}" --download-dir "${DOWNLOAD_DIR}" --disable-package