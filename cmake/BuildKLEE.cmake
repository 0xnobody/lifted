# BuildKLEE.cmake - Fetch and build KLEE using FetchContent
# TODO: It would probably be better to do this via ExternalProject_Add
# as currently configuring can take a while

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring KLEE ===")

include(FetchContent)

add_library(z3::libz3 STATIC IMPORTED GLOBAL)  # or SHARED if using shared library
set_target_properties(z3::libz3 PROPERTIES
    IMPORTED_LOCATION "${Z3_LIBRARIES}"
    INTERFACE_INCLUDE_DIRECTORIES "${Z3_INCLUDE_DIR}"
)

# Configuration options
set(KLEE_VERSION "master" CACHE STRING "KLEE version/branch to fetch")
set(KLEE_REPOSITORY "https://github.com/klee/klee.git" CACHE STRING "KLEE repository URL")
get_filename_component(KLEE_INSTALL_DIR "${CMAKE_BINARY_DIR}/klee-install" ABSOLUTE)

set(ENABLE_SOLVER_Z3 ON CACHE BOOL "Enable Z3" FORCE)
set(ENABLE_UNIT_TESTS OFF CACHE BOOL "Disable unit tests" FORCE)
set(ENABLE_SYSTEM_TESTS OFF CACHE BOOL "Disable system tests" FORCE)
set(ENABLE_POSIX_RUNTIME OFF CACHE BOOL "Disable POSIX runtime" FORCE)
set(ENABLE_KLEE_UCLIBC OFF CACHE BOOL "Disable uclibc" FORCE)

# Fetch and configure KLEE
FetchContent_Declare(
  klee
  GIT_REPOSITORY ${KLEE_REPOSITORY}
  GIT_TAG ${KLEE_VERSION}
  SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/klee"
  BINARY_DIR "${CMAKE_BINARY_DIR}/klee-build"
)

function(patch_cmake_lists TO_PATCH)
  file(READ "${TO_PATCH}" KLEE_CMAKE)
  string(REPLACE "CMAKE_SOURCE_DIR" "PROJECT_SOURCE_DIR" KLEE_CMAKE "${KLEE_CMAKE}")
  file(WRITE "${TO_PATCH}" "${KLEE_CMAKE}")
endfunction()

# Apply patch before making available
FetchContent_GetProperties(klee)
if(NOT klee_POPULATED)
  FetchContent_Populate(klee)
  
  set(klee_SOURCE_DIR "${klee_SOURCE_DIR}")
  set(klee_BINARY_DIR "${klee_BINARY_DIR}")

  patch_cmake_lists("${klee_SOURCE_DIR}/CMakeLists.txt")

  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/Fortify/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/Freestanding/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/Intrinsic/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/klee-eh-cxx/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/klee-libc/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/POSIX/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/Runtest/CMakeLists.txt")
  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/Sanitizer/CMakeLists.txt")

  patch_cmake_lists("${klee_SOURCE_DIR}/runtime/CMakeLists.txt")

  # Now add it as a subdirectory
  add_subdirectory(${klee_SOURCE_DIR} ${klee_BINARY_DIR})
endif()


# AFAIK KLEE doesn't provide a proper install target
add_library(libklee INTERFACE IMPORTED GLOBAL)
set_target_properties(libklee PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${klee_SOURCE_DIR}/include"
)
target_link_libraries(libklee INTERFACE kleeCore)

set(KLEE_RUNTIME_LIBRARY_PATH "${CMAKE_BINARY_DIR}/runtime/lib" CACHE STRING "Path to KLEE bitcode libraries" FORCE)

message(STATUS "=== KLEE configuration complete ===")
message(STATUS "")