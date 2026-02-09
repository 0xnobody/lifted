# BuildPolaris.cmake - Fetch and build Polaris using ExternalProject_Add

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring Polaris ===")

include(ExternalProject)

# Configuration options
set(POLARIS_VERSION "main" CACHE STRING "Polaris version/branch to fetch")
set(POLARIS_REPOSITORY "https://github.com/za233/Polaris-Obfuscator.git" CACHE STRING "Polaris repository URL")

# Allow toggling LLVM assertions if desired
set(LLVM_ENABLE_ASSERTIONS OFF CACHE BOOL "Enable LLVM assertions for Polaris build")

# Auto-detect CPU cores and set conservative default for parallel jobs
include(ProcessorCount)
ProcessorCount(N_CORES)
if(N_CORES EQUAL 0)
  set(N_CORES 4)  # Fallback if detection fails
endif()
math(EXPR DEFAULT_POLARIS_JOBS "${N_CORES} - 4")
if(DEFAULT_POLARIS_JOBS LESS 1)
  set(DEFAULT_POLARIS_JOBS 1)
endif()

# Limit parallel build jobs to prevent resource exhaustion
# Always use auto-detected value, but user can override via -DPOLARIS_BUILD_JOBS=X
set(POLARIS_BUILD_JOBS "${DEFAULT_POLARIS_JOBS}" CACHE STRING "Number of parallel build jobs for Polaris (lower to reduce RAM/CPU usage)" FORCE)
message(STATUS "Polaris will build with ${POLARIS_BUILD_JOBS} parallel jobs (detected ${N_CORES} cores)")

# Preferred source/build locations
set(POLARIS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/polaris")
set(POLARIS_BINARY_DIR "${CMAKE_BINARY_DIR}/polaris-build")

ExternalProject_Add(polaris
  GIT_REPOSITORY        ${POLARIS_REPOSITORY}
  GIT_TAG               ${POLARIS_VERSION}
  SOURCE_DIR            ${POLARIS_SOURCE_DIR}
  BINARY_DIR            ${POLARIS_BINARY_DIR}
  # Polaris' CMakeLists.txt lives under src/llvm
  SOURCE_SUBDIR         "src/llvm"
  # Mirror the original build.sh generator
  CMAKE_GENERATOR       "Ninja"

  # Drive configuration purely via CMake arguments
  CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=Release
    -DLLVM_ENABLE_PROJECTS=clang
    -DLLVM_TARGETS_TO_BUILD=X86
    -DLLVM_ENABLE_ASSERTIONS=${LLVM_ENABLE_ASSERTIONS}
    # Reduce compilation and linker memory usage (critical for WSL/low-memory systems)
    -DLLVM_USE_LINKER=lld
    -DLLVM_PARALLEL_LINK_JOBS=1
    -DLLVM_OPTIMIZED_TABLEGEN=ON
    -DLLVM_BUILD_TOOLS=OFF
    -DLLVM_INCLUDE_TESTS=OFF
    -DLLVM_INCLUDE_EXAMPLES=OFF
    -DLLVM_INCLUDE_BENCHMARKS=OFF
    # Propagate vcpkg/toolchain settings into the external build
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -DVCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}

  # Limit parallel jobs to prevent resource exhaustion
  BUILD_COMMAND ninja -j ${POLARIS_BUILD_JOBS}

  # No install step; keep the build local
  INSTALL_COMMAND ""

  # Quality-of-life options
  UPDATE_DISCONNECTED 1
  # LOG_CONFIGURE 1  # Disabled to show build progress in console
  # LOG_BUILD 1      # Disabled to show build progress in console
  
  # Show build output in real-time
  USES_TERMINAL_BUILD YES
  USES_TERMINAL_CONFIGURE YES
)

# Optional: an interface target other targets can depend on
add_library(polaris_external INTERFACE)
add_dependencies(polaris_external polaris)

set(POLARIS_CLANG_PATH "${POLARIS_BINARY_DIR}/bin/clang" CACHE PATH "Path to Polaris clang executable")

set(POLARIS_PASSES "sub,mba,bcf" CACHE STRING "Comma-separated list of Polaris passes to enable. Passes available: fla,gvenc,indcall,indbr,alias,bcf,sub,merge,mba")

message(STATUS "=== POLARIS configuration complete ===")
message(STATUS "")
