#!/usr/bin/env bash
set -euo pipefail

# Get absolute path to your project root
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Define where the Remill submodule lives
KLEE_DIR="${REPO_DIR}/external/klee"

echo "[+] Building Klee..."

BUILD_DIR="${REPO_DIR}/build/klee-build"
DOWNLOAD_DIR="${REPO_DIR}/downloads/lifting-bits-downloads"

mkdir -p "${BUILD_DIR}"

TOOLCHAIN_FILE="${DOWNLOAD_DIR}/vcpkg_ubuntu-22.04_llvm-16_amd64/scripts/buildsystems/vcpkg.cmake"

cmake -B "${BUILD_DIR}" -S "${KLEE_DIR}" -DENABLE_UNIT_TESTS=OFF -DENABLE_SYSTEM_TESTS=OFF -DENABLE_SOLVER_Z3=ON -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}"

make -C "${BUILD_DIR}"