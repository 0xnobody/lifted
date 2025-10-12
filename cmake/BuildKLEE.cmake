# BuildKLEE.cmake - Fetch and build KLEE using FetchContent

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring KLEE ===")

include(FetchContent)

# Configuration options
set(KLEE_VERSION "master" CACHE STRING "KLEE version/branch to fetch")
set(KLEE_REPOSITORY "https://github.com/klee/klee.git" CACHE STRING "KLEE repository URL")

# Use absolute path for install directory
get_filename_component(KLEE_INSTALL_DIR "${CMAKE_BINARY_DIR}/klee-install" ABSOLUTE)

set(ENABLE_SOLVER_Z3 ON CACHE BOOL "Enable Z3" FORCE)
set(ENABLE_UNIT_TESTS OFF CACHE BOOL "Disable unit tests" FORCE)
set(ENABLE_SYSTEM_TESTS OFF CACHE BOOL "Disable system tests" FORCE)
set(ENABLE_POSIX_RUNTIME OFF CACHE BOOL "Disable POSIX runtime" FORCE)
set(ENABLE_KLEE_UCLIBC OFF CACHE BOOL "Disable uclibc" FORCE)

# Fetch KLEE at configure time
FetchContent_Declare(
  klee
  GIT_REPOSITORY ${KLEE_REPOSITORY}
  GIT_TAG ${KLEE_VERSION}
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/klee"
  BINARY_DIR "${CMAKE_BINARY_DIR}/klee-build"
)

FetchContent_Populate(klee)

file(READ "${klee_SOURCE_DIR}/CMakeLists.txt" KLEE_CMAKE)
string(REPLACE "CMAKE_SOURCE_DIR" "PROJECT_SOURCE_DIR" KLEE_CMAKE "${KLEE_CMAKE}")
file(WRITE "${klee_SOURCE_DIR}/CMakeLists.txt" "${KLEE_CMAKE}")

FetchContent_MakeAvailable(klee)

message(STATUS "=== KLEE configuration complete ===")
message(STATUS "")