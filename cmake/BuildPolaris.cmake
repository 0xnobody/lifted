# BuildPolaris.cmake - Fetch and build Polaris during configure time

# Verify vcpkg toolchain is configured
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message(FATAL_ERROR "CMAKE_TOOLCHAIN_FILE not set. BootstrapVcpkg should have been called before project().")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET)
  message(FATAL_ERROR "VCPKG_TARGET_TRIPLET not set. BootstrapVcpkg should have been called before project().")
endif()

message(STATUS "=== Fetching and Configuring Polaris ===")

include(FetchContent)
include(ProcessorCount)

# Configuration options
set(POLARIS_VERSION "main" CACHE STRING "Polaris version/branch to fetch")
set(POLARIS_REPOSITORY "https://github.com/za233/Polaris-Obfuscator.git" CACHE STRING "Polaris repository URL")
set(LLVM_ENABLE_ASSERTIONS OFF CACHE BOOL "Enable LLVM assertions for Polaris build")
set(POLARIS_PASSES "sub,mba,bcf" CACHE STRING "Comma-separated list of Polaris passes to enable. Passes available: fla,gvenc,indcall,indbr,alias,bcf,sub,merge,mba")

ProcessorCount(N_CORES)
if(N_CORES EQUAL 0)
  set(N_CORES 4)
endif()
math(EXPR DEFAULT_POLARIS_JOBS "${N_CORES} / 4")
if(DEFAULT_POLARIS_JOBS LESS 1)
  set(DEFAULT_POLARIS_JOBS 1)
elseif(DEFAULT_POLARIS_JOBS GREATER 4)
  set(DEFAULT_POLARIS_JOBS 4)
endif()

if(NOT DEFINED CACHE{POLARIS_BUILD_JOBS})
  set(POLARIS_BUILD_JOBS "${DEFAULT_POLARIS_JOBS}" CACHE STRING "Number of parallel build jobs for Polaris (lower to reduce RAM/CPU usage)")
endif()
message(STATUS "Polaris will build with ${POLARIS_BUILD_JOBS} parallel jobs (detected ${N_CORES} cores)")

# Preferred source/build locations
set(POLARIS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/polaris")
set(POLARIS_BINARY_DIR "${CMAKE_BINARY_DIR}/polaris-build")
set(POLARIS_CLANG_PATH "${POLARIS_BINARY_DIR}/bin/clang" CACHE PATH "Path to Polaris clang executable" FORCE)

function(_run_polaris_command STEP)
  set(options)
  set(oneValueArgs WORKING_DIRECTORY)
  set(multiValueArgs COMMAND)
  cmake_parse_arguments(POLARIS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT POLARIS_COMMAND)
    message(FATAL_ERROR "_run_polaris_command requires COMMAND")
  endif()

  string(JOIN " " _pretty_command ${POLARIS_COMMAND})
  execute_process(
    COMMAND ${POLARIS_COMMAND}
    WORKING_DIRECTORY "${POLARIS_WORKING_DIRECTORY}"
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _stdout
    ERROR_VARIABLE _stderr
  )

  if(NOT _result EQUAL 0)
    message(FATAL_ERROR
      "Polaris ${STEP} failed with exit code ${_result}.\n"
      "Command: ${_pretty_command}\n"
      "--- stdout ---\n${_stdout}\n"
      "--- stderr ---\n${_stderr}")
  endif()
endfunction()

FetchContent_Declare(
  polaris
  GIT_REPOSITORY ${POLARIS_REPOSITORY}
  GIT_TAG ${POLARIS_VERSION}
  GIT_SHALLOW FALSE
  SOURCE_DIR "${POLARIS_SOURCE_DIR}"
)
FetchContent_GetProperties(polaris)
if(NOT polaris_POPULATED)
  FetchContent_Populate(polaris)
endif()

set(_polaris_configure_command
  ${CMAKE_COMMAND}
  -S "${POLARIS_SOURCE_DIR}/src/llvm"
  -B "${POLARIS_BINARY_DIR}"
  -G "${CMAKE_GENERATOR}"
)
if(CMAKE_GENERATOR_PLATFORM)
  list(APPEND _polaris_configure_command -A "${CMAKE_GENERATOR_PLATFORM}")
endif()
if(CMAKE_GENERATOR_TOOLSET)
  list(APPEND _polaris_configure_command -T "${CMAKE_GENERATOR_TOOLSET}")
endif()
if(CMAKE_MAKE_PROGRAM)
  list(APPEND _polaris_configure_command -DCMAKE_MAKE_PROGRAM:FILEPATH=${CMAKE_MAKE_PROGRAM})
endif()
if(CMAKE_C_COMPILER)
  list(APPEND _polaris_configure_command -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER})
endif()
if(CMAKE_CXX_COMPILER)
  list(APPEND _polaris_configure_command -DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER})
endif()
list(APPEND _polaris_configure_command
  -DCMAKE_BUILD_TYPE=Release
  -DLLVM_ENABLE_PROJECTS=clang
  -DLLVM_TARGETS_TO_BUILD=X86
  -DLLVM_ENABLE_ASSERTIONS=${LLVM_ENABLE_ASSERTIONS}
  -DLLVM_USE_LINKER=lld
  -DLLVM_PARALLEL_LINK_JOBS=1
  -DLLVM_OPTIMIZED_TABLEGEN=ON
  -DLLVM_BUILD_TOOLS=OFF
  -DLLVM_INCLUDE_TESTS=OFF
  -DLLVM_INCLUDE_EXAMPLES=OFF
  -DLLVM_INCLUDE_BENCHMARKS=OFF
  -DCLANG_ENABLE_ARCMT=OFF
  -DCLANG_ENABLE_STATIC_ANALYZER=OFF
  -DCLANG_INCLUDE_DOCS=OFF
  -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE}
  -DVCPKG_TARGET_TRIPLET:STRING=${VCPKG_TARGET_TRIPLET}
)

_run_polaris_command(
  "configure"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMAND ${_polaris_configure_command}
)

# Always ask the external build system to ensure clang is current; if it is already
# up to date, the build tool performs a no-op instead of rebuilding blindly.
_run_polaris_command(
  "build"
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  COMMAND
    ${CMAKE_COMMAND} --build "${POLARIS_BINARY_DIR}" --target clang --parallel ${POLARIS_BUILD_JOBS}
)

if(NOT EXISTS "${POLARIS_CLANG_PATH}")
  message(FATAL_ERROR "Polaris clang executable was not produced at ${POLARIS_CLANG_PATH}")
endif()

message(STATUS "=== POLARIS configuration complete ===")
message(STATUS "")
