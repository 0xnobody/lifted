# SouperExternal.cmake
cmake_minimum_required(VERSION 3.20)

include(ExternalProject)

# ============================================================================
# Configuration
# ============================================================================

set(SOUPER_BUILD_TYPE "Release" CACHE STRING "Build type for Souper")
set(SOUPER_INSTALL_DIR "${CMAKE_BINARY_DIR}/souper-install" CACHE PATH "Souper installation")

# Source and build directories
set(Z3_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/z3")
set(HIREDIS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/hiredis")
set(ALIVE2_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/alive2")
set(KLEE_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/klee_expr")
set(SOUPER_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/souper")

set(Z3_BINARY_DIR "${CMAKE_BINARY_DIR}/z3-build")
set(HIREDIS_BINARY_DIR "${CMAKE_BINARY_DIR}/hiredis-build")
set(ALIVE2_BINARY_DIR "${CMAKE_BINARY_DIR}/alive2-build")
set(KLEE_BINARY_DIR "${CMAKE_BINARY_DIR}/klee_expr-build")
set(SOUPER_BINARY_DIR "${CMAKE_BINARY_DIR}/souper-build")

# ============================================================================
# Find LLVM
# ============================================================================

if(NOT DEFINED LLVM_DIR)
    message(FATAL_ERROR "LLVM_DIR must be set")
endif()

find_package(LLVM 16 REQUIRED CONFIG)
find_program(LLVM_CONFIG_BINARY NAMES llvm-config HINTS ${LLVM_TOOLS_BINARY_DIR} REQUIRED)

get_filename_component(LLVM_CMAKE_DIR "${LLVM_DIR}" DIRECTORY)
get_filename_component(LLVM_PREFIX "${LLVM_CMAKE_DIR}" DIRECTORY)

message(STATUS "LLVM_DIR: ${LLVM_DIR}")
message(STATUS "LLVM_PREFIX: ${LLVM_PREFIX}")

# ============================================================================
# Build Dependencies
# ============================================================================

ExternalProject_Add(z3_external
    GIT_REPOSITORY "https://github.com/Z3Prover/z3.git"
    GIT_TAG "z3-4.12.2"
    SOURCE_DIR "${Z3_SOURCE_DIR}"
    BINARY_DIR "${Z3_BINARY_DIR}"
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${SOUPER_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_CXX_FLAGS=-include\ cstdint
        -DCMAKE_C_FLAGS=-include\ stdint.h
        -DBUILD_SHARED_LIBS=ON
        -DZ3_BUILD_LIBZ3_SHARED=ON
        -DZ3_BUILD_PYTHON_BINDINGS=OFF
        -DZ3_BUILD_JAVA_BINDINGS=OFF
        -DZ3_BUILD_DOTNET_BINDINGS=OFF
        -DZ3_BUILD_EXAMPLES=OFF
        -DZ3_BUILD_TEST_EXECUTABLES=OFF
    BUILD_BYPRODUCTS
        <INSTALL_DIR>/lib/libz3.so
        <INSTALL_DIR>/include/z3.h
    UPDATE_DISCONNECTED 1
    LOG_CONFIGURE TRUE
    LOG_BUILD TRUE
    LOG_INSTALL TRUE
)

ExternalProject_Get_Property(z3_external INSTALL_DIR)
set(Z3_INSTALL_DIR "${INSTALL_DIR}")

ExternalProject_Add(hiredis_external
    GIT_REPOSITORY "https://github.com/redis/hiredis.git"
    GIT_TAG "667dbf536524ba3f28c1d964793db1055c5a64f2"
    SOURCE_DIR "${HIREDIS_SOURCE_DIR}"
    BINARY_DIR "${HIREDIS_BINARY_DIR}"
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${SOUPER_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DENABLE_SSL=OFF
        -DDISABLE_TESTS=ON
    UPDATE_DISCONNECTED 1
    LOG_CONFIGURE TRUE
    LOG_BUILD TRUE
    LOG_INSTALL TRUE
)

ExternalProject_Get_Property(hiredis_external INSTALL_DIR)
set(HIREDIS_INSTALL_DIR "${INSTALL_DIR}")

ExternalProject_Add(alive2_external
    GIT_REPOSITORY "https://github.com/manasij7479/alive2.git"
    GIT_TAG "v4"
    SOURCE_DIR "${ALIVE2_SOURCE_DIR}"
    BINARY_DIR "${ALIVE2_BINARY_DIR}"
    DEPENDS z3_external
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${SOUPER_BUILD_TYPE}
        -DCMAKE_PREFIX_PATH=${LLVM_PREFIX}\;${Z3_INSTALL_DIR}
        -DCMAKE_CXX_FLAGS=-include\ cstdint
        -DCMAKE_C_FLAGS=-include\ stdint.h
        -DZ3_DIR=${Z3_INSTALL_DIR}/lib/cmake/z3
        -DZ3_INCLUDE_DIR=${Z3_INSTALL_DIR}/include
        -DZ3_LIBRARIES=${Z3_INSTALL_DIR}/lib/libz3.so
        -DBUILD_TV=OFF
        -DBUILD_SHARED_LIBS=OFF
    INSTALL_COMMAND ""
    UPDATE_DISCONNECTED 1
    LOG_CONFIGURE TRUE
    LOG_BUILD TRUE
)

ExternalProject_Add(klee_expr_external
    GIT_REPOSITORY "https://github.com/regehr/klee.git"
    GIT_TAG "klee-for-souper-17-2"
    SOURCE_DIR "${KLEE_SOURCE_DIR}"
    BINARY_DIR "${KLEE_BINARY_DIR}"
    DEPENDS z3_external
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${SOUPER_BUILD_TYPE}
        -DCMAKE_CXX_STANDARD=20
        -DCMAKE_CXX_FLAGS=-include\ cstdint
        -DCMAKE_C_FLAGS=-include\ stdint.h
        -DCMAKE_CXX_STANDARD_REQUIRED=ON
        -DLLVM_CONFIG_BINARY=${LLVM_CONFIG_BINARY}
        -DLLVM_DIR=${LLVM_DIR}
        -DZ3_INCLUDE_DIR=${Z3_INSTALL_DIR}/include
        -DZ3_LIBRARIES=${Z3_INSTALL_DIR}/lib/libz3.so
        -DENABLE_SOLVER_Z3=ON
        -DENABLE_UNIT_TESTS=OFF
        -DENABLE_SYSTEM_TESTS=OFF
        -DENABLE_KLEE_UCLIBC=OFF
        -DENABLE_POSIX_RUNTIME=OFF
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target kleaverExpr
    INSTALL_COMMAND ""
    UPDATE_DISCONNECTED 1
    LOG_CONFIGURE TRUE
    LOG_BUILD TRUE
)

# ============================================================================
# Build Souper
# ============================================================================

ExternalProject_Add(souper_external
    GIT_REPOSITORY "https://github.com/0xnobody/souper.git"
    GIT_TAG "cmake-compat"
    SOURCE_DIR "${SOUPER_SOURCE_DIR}"
    BINARY_DIR "${SOUPER_BINARY_DIR}"
    DEPENDS hiredis_external alive2_external klee_expr_external z3_external
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${SOUPER_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=${SOUPER_INSTALL_DIR}
        -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
        -DLLVM_DIR=${LLVM_DIR}
        -DCMAKE_PREFIX_PATH=${LLVM_PREFIX}
        -Dzstd_DIR=${LLVM_PREFIX}/share/zstd
        -Dzstd_INCLUDE_DIR=${LLVM_PREFIX}/include
        -Dzstd_LIBRARY=${LLVM_PREFIX}/lib/libzstd.a
        -DLLVM_CONFIG_EXECUTABLE=${LLVM_CONFIG_BINARY}
        -DALIVE_SRCDIR=${ALIVE2_SOURCE_DIR}
        -DALIVE_BUILDDIR=${ALIVE2_BINARY_DIR}
        -DZ3_INSTALL_DIR=${Z3_INSTALL_DIR}
        -DHIREDIS_INSTALL_DIR=${HIREDIS_INSTALL_DIR}
        -DUSE_EXTERNAL_KLEE=ON
        -DKLEE_INCLUDE_DIR=${KLEE_SOURCE_DIR}/include
        -DKLEE_LIBRARY=${KLEE_BINARY_DIR}/lib/libkleaverExpr.a
    UPDATE_DISCONNECTED 1
    LOG_CONFIGURE TRUE
    LOG_BUILD TRUE
    LOG_INSTALL TRUE
)

# ============================================================================
# Export Targets
# ============================================================================

add_executable(souper IMPORTED GLOBAL)
add_dependencies(souper souper_external)
set_target_properties(souper PROPERTIES
    IMPORTED_LOCATION "${SOUPER_INSTALL_DIR}/bin/souper"
)

add_executable(souper-check IMPORTED GLOBAL)
add_dependencies(souper-check souper_external)
set_target_properties(souper-check PROPERTIES
    IMPORTED_LOCATION "${SOUPER_INSTALL_DIR}/bin/souper-check"
)

# Add Souper interface library for linking
add_library(Souper INTERFACE)
add_dependencies(Souper souper_external)

target_include_directories(Souper INTERFACE
    "${SOUPER_SOURCE_DIR}/include"
    "${SOUPER_BINARY_DIR}/include"  # For generated headers like GetSolver.h
    "${SOUPER_INSTALL_DIR}/include"
)

target_link_directories(Souper INTERFACE
    "${SOUPER_INSTALL_DIR}/lib"
)

set(SOUPER_EXECUTABLE "${SOUPER_INSTALL_DIR}/bin/souper" CACHE FILEPATH "Path to souper")
set(SOUPER_CHECK_EXECUTABLE "${SOUPER_INSTALL_DIR}/bin/souper-check" CACHE FILEPATH "Path to souper-check")

message(STATUS "========================================")
message(STATUS "Souper External Project Configuration:")
message(STATUS "  Sources: ${CMAKE_SOURCE_DIR}/external/")
message(STATUS "  Build: ${CMAKE_BINARY_DIR}")
message(STATUS "  Install: ${SOUPER_INSTALL_DIR}")
message(STATUS "========================================")
