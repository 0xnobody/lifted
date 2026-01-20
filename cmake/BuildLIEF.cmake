# BuildLIEF.cmake - Fetch and build LIEF using FetchContent
# TODO: It would probably be better to do this via ExternalProject_Add
# as currently configuring can take a while

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring LIEF ===")

include(FetchContent)

# Configuration options
set(LIEF_VERSION "0.13.0" CACHE STRING "Remill version/branch to fetch")
set(LIEF_REPOSITORY "https://github.com/lief-project/LIEF.git" CACHE STRING "LIEF repository URL")

# Fetch Remill at configure time
FetchContent_Declare(
  lief
  GIT_REPOSITORY ${LIEF_REPOSITORY}
  GIT_TAG ${LIEF_VERSION}
  GIT_SHALLOW FALSE
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/lief"
  BINARY_DIR "${CMAKE_BINARY_DIR}/lief-build"
)

FetchContent_MakeAvailable(lief)

message(STATUS "=== LIEF configuration complete ===")
message(STATUS "")