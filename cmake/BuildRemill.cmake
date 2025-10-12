# BuildRemill.cmake - Fetch and build Remill using FetchContent

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring Remill ===")

include(FetchContent)

# Configuration options
set(REMILL_VERSION "7182636a687e5e005e3336108a653de3aec0362b" CACHE STRING "Remill version/branch to fetch")
set(REMILL_REPOSITORY "https://github.com/lifting-bits/remill.git" CACHE STRING "Remill repository URL")

# Fetch Remill at configure time
FetchContent_Declare(
  remill
  GIT_REPOSITORY ${REMILL_REPOSITORY}
  GIT_TAG ${REMILL_VERSION}
  GIT_SHALLOW FALSE
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/remill"
  BINARY_DIR "${CMAKE_BINARY_DIR}/remill-build"
)

FetchContent_MakeAvailable(remill)

message(STATUS "=== Remill configuration complete ===")
message(STATUS "")