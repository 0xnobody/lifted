# Get the remill include directories from the target
if(NOT TARGET remill_settings)
    message(FATAL_ERROR "Could not find target 'remill_settings' (did remill update?)")
endif()
get_target_property(HELPER_REMILL_INCLUDE_DIR remill_settings INTERFACE_INCLUDE_DIRECTORIES)
if(HELPER_REMILL_INCLUDE_DIR STREQUAL "HELPER_REMILL_INCLUDE_DIR-NOTFOUND")
    message(FATAL_ERROR "Could not determine remill include directory")
endif()

get_target_property(HELPER_KLEE_INCLUDE_DIR libklee INTERFACE_INCLUDE_DIRECTORIES)
if(HELPER_KLEE_INCLUDE_DIR STREQUAL "HELPER_KLEE_INCLUDE_DIR-NOTFOUND")
    message(FATAL_ERROR "Could not determine klee include directory")
endif()

# Locate the clang executable
set(HELPER_CLANG_EXECUTABLE ${CMAKE_BC_COMPILER})
if(NOT EXISTS "${HELPER_CLANG_EXECUTABLE}")
    message(FATAL_ERROR "Could not find: ${HELPER_CLANG_EXECUTABLE}")
endif()

# Locate llvm-link
get_filename_component(HELPER_LLVM_LINK_EXECUTABLE ${CMAKE_BC_COMPILER} PATH)
if (NOT EXISTS "${HELPER_LLVM_LINK_EXECUTABLE}")
    message(FATAL_ERROR "Could not find llvm-link in: ${HELPER_LLVM_LINK_EXECUTABLE}")
endif()
set(HELPER_LLVM_LINK_EXECUTABLE "${HELPER_LLVM_LINK_EXECUTABLE}/llvm-link")

set(HELPER_CLANG_FLAGS
    -emit-llvm
    -std=c++20
    -O3
    -Werror
    -Wno-gnu-inline-cpp-without-extern
    -Wno-return-type-c-linkage

    -fno-discard-value-names
    -fstrict-aliasing
    -fno-slp-vectorize
    #-mllvm -enable-tbaa=true
    "-I${HELPER_REMILL_INCLUDE_DIR}"
    "-I${HELPER_KLEE_INCLUDE_DIR}"
    -Wno-unused-command-line-argument
)

message(STATUS "[helpers] Remill include: ${HELPER_REMILL_INCLUDE_DIR}")
message(STATUS "[helpers] Clang: ${HELPER_CLANG_EXECUTABLE}")
message(STATUS "[helpers] Flags: ${HELPER_CLANG_FLAGS}")

set(HELPER_BINARY_DIR "${CMAKE_BINARY_DIR}/helpers")
set(HELPER_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(HELPER_SOURCES
    "${HELPER_DIR}/abi-helper.cpp"
    "${HELPER_DIR}/deobfuscation-helper.cpp"
    "${HELPER_DIR}/verification-helper.cpp"
    "${HELPER_DIR}/verification-harness.cpp"
    "${HELPER_DIR}/symbolic-helper.cpp"
    "${HELPER_DIR}/state-utils.cpp"
)

foreach(source ${HELPER_SOURCES})
    get_filename_component(name "${source}" NAME_WE)
    set(ll "${HELPER_BINARY_DIR}/${name}.ll")

    add_custom_command(
        OUTPUT ${ll}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${HELPER_BINARY_DIR}
        COMMAND "${HELPER_CLANG_EXECUTABLE}" -S -emit-llvm -o "${ll}" ${source} ${HELPER_CLANG_FLAGS}
        DEPENDS ${source}
        COMMENT "Compiling helper: ${name}.cpp"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    list(APPEND HELPER_OUTPUTS ${ll})
endforeach()

set(HELPERS_ABI_PATH "${HELPER_BINARY_DIR}/abi-helper.ll" CACHE STRING "abi-helper.ll path")
set(HELPERS_DEOBFUSCATION_INTRINSICS_PATH "${HELPER_BINARY_DIR}/deobfuscation-helper.ll" CACHE STRING "deobfuscation-helper.ll path")
set(HELPERS_VERIFICATION_INTRINSICS_PATH "${HELPER_BINARY_DIR}/verification-helper.ll" CACHE STRING "verification-helper.ll path")
set(HELPERS_VERIFICATION_HARNESS_PATH "${HELPER_BINARY_DIR}/verification-harness.ll" CACHE STRING "verification-harness.ll path")
set(HELPERS_STATE_UTILS_PATH "${HELPER_BINARY_DIR}/state-utils.ll" CACHE STRING "state-utils.ll path")
set(HELPERS_SYMBOLIC_PATH "${HELPER_BINARY_DIR}/symbolic-helper.ll" CACHE STRING "symbolic-helper.ll path")

add_custom_target(helpers ALL
    DEPENDS ${HELPER_OUTPUTS}
    SOURCES ${HELPER_SOURCES}
)

