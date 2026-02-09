cmake_minimum_required(VERSION 3.21)

# Set policies to suppress warnings
if(POLICY CMP0160)
  cmake_policy(SET CMP0160 OLD)  # Allow setting read-only target properties (for Remill)
endif()

if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)  # Allow FetchContent_Populate (for KLEE patching)
endif()

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "Install prefix" FORCE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Bootstrap vcpkg (BEFORE project!)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  include(BootstrapVcpkg)
  bootstrap_vcpkg_toolchain()
endif()

project(lifted-root)

include(BuildRemill)
include(BuildKLEE)
include(BuildLIEF)
include(BuildPolaris)
include(BuildSouper)
include(BuildUnicorn)

add_subdirectory(src)