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
    # Propagate vcpkg/toolchain settings into the external build
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    -DVCPKG_TARGET_TRIPLET=${VCPKG_TARGET_TRIPLET}

  # No install step; keep the build local
  INSTALL_COMMAND ""

  # Quality-of-life options
  UPDATE_DISCONNECTED 1
  LOG_CONFIGURE 1
  LOG_BUILD 1
)

# Optional: an interface target other targets can depend on
add_library(polaris_external INTERFACE)
add_dependencies(polaris_external polaris)

set(POLARIS_CLANG_PATH "${POLARIS_BINARY_DIR}/bin/clang" CACHE PATH "Path to Polaris clang executable")

set(POLARIS_PASSES "sub,mba,bcf" CACHE STRING "Comma-separated list of Polaris passes to enable. Passes available: fla,gvenc,indcall,indbr,alias,bcf,sub,merge,mba")

message(STATUS "=== POLARIS configuration complete ===")
message(STATUS "")
