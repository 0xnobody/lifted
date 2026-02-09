# BuildRemill.cmake - Fetch and build Remill using FetchContent
# TODO: It would probably be better to do this via ExternalProject_Add
# as currently configuring can take a while

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring Remill ===")

# Set policy to allow Remill to set read-only target properties
if(POLICY CMP0160)
  cmake_policy(SET CMP0160 OLD)
endif()

include(FetchContent)

# Configuration options
# version is final commit which has LLVM 16 support
set(REMILL_VERSION "7182636a687e5e005e3336108a653de3aec0362b" CACHE STRING "Remill version/branch to fetch")
set(REMILL_REPOSITORY "https://github.com/lifting-bits/remill.git" CACHE STRING "Remill repository URL")

# Fetch Remill at configure time
# Force include cstdint for newer GCC versions
set(REMILL_EXTRA_CXX_FLAGS "-include cstdint" CACHE STRING "Extra C++ flags for Remill" FORCE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include cstdint" CACHE STRING "" FORCE)

FetchContent_Declare(
  remill
  GIT_REPOSITORY ${REMILL_REPOSITORY}
  GIT_TAG ${REMILL_VERSION}
  GIT_SHALLOW FALSE
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/remill"
  BINARY_DIR "${CMAKE_BINARY_DIR}/remill-build"
)

# Patch Remill's CMakeLists.txt to set CMP0160 policy
FetchContent_GetProperties(remill)
if(NOT remill_POPULATED)
  FetchContent_Populate(remill)
  
  # Patch main CMakeLists.txt to set policy
  file(READ "${remill_SOURCE_DIR}/CMakeLists.txt" REMILL_CMAKE)
  string(FIND "${REMILL_CMAKE}" "if(POLICY CMP0160)" HAS_POLICY)
  if(HAS_POLICY EQUAL -1)
    string(REGEX REPLACE "(cmake_minimum_required[^\n]+)" "\\1\n\n# Set policy to allow setting read-only target properties\nif(POLICY CMP0160)\n  cmake_policy(SET CMP0160 OLD)\nendif()" REMILL_CMAKE "${REMILL_CMAKE}")
    file(WRITE "${remill_SOURCE_DIR}/CMakeLists.txt" "${REMILL_CMAKE}")
  endif()
  
  add_subdirectory(${remill_SOURCE_DIR} ${remill_BINARY_DIR})
else()
  add_subdirectory(${remill_SOURCE_DIR} ${remill_BINARY_DIR})
endif()

message(STATUS "=== Remill configuration complete ===")
message(STATUS "")