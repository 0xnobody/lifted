# EvalHelpers.cmake
# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────
#   register_obfuscator(NAME <id>
#                       COMPILER <path>
#                       FLAGS    <flag> ...)
#
#   define_eval_target(NAME    <id>
#                      SOURCE  <file>
#                      [LANGUAGE C|CXX]           # default: inferred from ext
#                      [FUNCTIONS <fn> ...]       # override auto-detect
#                      [COMPILE_OPTIONS <opt> ...])
#
#   define_eval_suite(NAME      <suite-id>
#                    TARGETS   <target-id> ...
#                    [OBFUSCATORS <obfuscator-id> ...])
#
# Outputs per target  : lib<id>.so  +  <id>.targets.csv
# Outputs per suite   : <suite-id>.targets.csv  (so_path,targets_csv_path)
# ─────────────────────────────────────────────────────────────────────────────

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(_EVAL_SCRIPTS_DIR "${CMAKE_CURRENT_LIST_DIR}/../scripts"
    CACHE INTERNAL "Directory containing evaluation Python scripts")

# Optimization level used when compiling evaluation targets (plain and obfuscated).
# Expressed as the flag suffix: O0, O1, O2, O3, Os, Oz.
# Override via -DEVAL_OPT_LEVEL=O2 on the cmake command line.
if(NOT DEFINED CACHE{EVAL_OPT_LEVEL})
    set(EVAL_OPT_LEVEL "O0"
        CACHE STRING "Optimization level for evaluation targets (O0/O1/O2/O3/Os/Oz)")
endif()
message(STATUS "[EvalHelpers] Optimization level: -${EVAL_OPT_LEVEL}")

# ── register_obfuscator ───────────────────────────────────────────────────────
# Stores an obfuscator definition as global CMake properties so it can be
# referenced by name inside any define_eval_suite() call.
#
# Usage:
#   register_obfuscator(NAME polaris
#                       COMPILER /path/to/clang
#                       FLAGS -mllvm -passes="sub,mba,bcf")
# ─────────────────────────────────────────────────────────────────────────────
function(register_obfuscator)
    cmake_parse_arguments(OBF "" "NAME;COMPILER" "FLAGS" ${ARGN})

    if(NOT OBF_NAME OR NOT OBF_COMPILER)
        message(FATAL_ERROR "register_obfuscator: NAME and COMPILER are required")
    endif()

    set_property(GLOBAL PROPERTY _EVAL_OBF_${OBF_NAME}_COMPILER "${OBF_COMPILER}")
    set_property(GLOBAL PROPERTY _EVAL_OBF_${OBF_NAME}_FLAGS     "${OBF_FLAGS}")
    message(STATUS "[EvalHelpers] Registered obfuscator '${OBF_NAME}': ${OBF_COMPILER}")
endfunction()

# ── define_eval_target ────────────────────────────────────────────────────────
# Defines a single evaluation binary target.
#
# Creates:
#   eval-<id>-obj   OBJECT library  – used for clean symbol extraction
#   eval-<id>       SHARED library  – the .so that gets lifted
#   <id>.targets.csv  – func_name,addr pairs (generated post-build)
#
# Sets in parent scope:
#   EVAL_TARGET_<ID_UPPER>_SO   absolute path to the .so
#   EVAL_TARGET_<ID_UPPER>_CSV  absolute path to the .targets.csv
# ─────────────────────────────────────────────────────────────────────────────
function(define_eval_target)
    cmake_parse_arguments(ET "" "NAME;SOURCE;LANGUAGE" "FUNCTIONS;COMPILE_OPTIONS" ${ARGN})

    if(NOT ET_NAME OR NOT ET_SOURCE)
        message(FATAL_ERROR "define_eval_target: NAME and SOURCE are required")
    endif()

    # Resolve source to absolute path
    if(NOT IS_ABSOLUTE "${ET_SOURCE}")
        set(ET_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/${ET_SOURCE}")
    endif()

    # Infer language from extension if not specified
    if(NOT ET_LANGUAGE)
        get_filename_component(_ext "${ET_SOURCE}" EXT)
        if(_ext STREQUAL ".c")
            set(ET_LANGUAGE C)
        else()
            set(ET_LANGUAGE CXX)
        endif()
    endif()

    # Default compile flags matching the original synthetic setup.
    # Optimization level is controlled globally via EVAL_OPT_LEVEL cache variable.
    set(_default_opts
        -${EVAL_OPT_LEVEL} -DNDEBUG
        -fno-stack-protector
        -fno-tree-vectorize
        -fPIC
    )

    # ── OBJECT library (used for potential multi-TU composition in suites) ──────
    set(_obj_target "eval-${ET_NAME}-obj")
    add_library(${_obj_target} OBJECT "${ET_SOURCE}")
    set_target_properties(${_obj_target} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        LINKER_LANGUAGE ${ET_LANGUAGE}
    )
    target_compile_options(${_obj_target} PRIVATE
        ${_default_opts}
        ${ET_COMPILE_OPTIONS}
    )

    # ── SHARED library ────────────────────────────────────────────────────────
    set(_so_target "eval-${ET_NAME}")
    add_library(${_so_target} SHARED $<TARGET_OBJECTS:${_obj_target}>)
    set_target_properties(${_so_target} PROPERTIES
        OUTPUT_NAME "eval-${ET_NAME}"
        LINKER_LANGUAGE ${ET_LANGUAGE}
    )

    # ── CSV: extract functions → <name>.targets.csv ────────────────────────────    
    # Uses add_custom_command(OUTPUT) so CMake tracks the CSV as a real file
    # artifact with timestamp-based dependency checking.  This means:
    #   • Missing CSV     → always regenerated on next build (even if .so unchanged)
    #   • .so rebuilt     → CSV regenerated (file timestamp dependency via target)
    #   • Nothing changed → no-op
    set(_so_path    "$<TARGET_FILE:${_so_target}>")
    # Deterministic path to the object file: CMakeFiles/<target>.dir/<src>.o
    get_filename_component(_src_name "${ET_SOURCE}" NAME)
    set(_obj_file   "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${_obj_target}.dir/${_src_name}.o")
    set(_csv_path   "${CMAKE_CURRENT_BINARY_DIR}/${ET_NAME}.targets.csv")
    set(_script     "${_EVAL_SCRIPTS_DIR}/extract_functions.py")

    # Build optional --functions args
    set(_fn_args "")
    if(ET_FUNCTIONS)
        foreach(_fn IN LISTS ET_FUNCTIONS)
            list(APPEND _fn_args "--functions" "${_fn}")
        endforeach()
    endif()

    add_custom_command(
        OUTPUT  "${_csv_path}"
        COMMAND ${Python3_EXECUTABLE} "${_script}"
                --object "${_obj_file}"
                --so     "${_so_path}"
                --output "${_csv_path}"
                ${_fn_args}
        DEPENDS ${_so_target} "${_obj_file}"
        COMMENT "[EvalHelpers] Extracting functions from ${ET_NAME} -> ${ET_NAME}.targets.csv"
        VERBATIM
    )

    # Named custom target so the CSV participates in the default build graph
    # and so define_eval_suite can depend on it by name.
    add_custom_target("eval-${ET_NAME}-csv" DEPENDS "${_csv_path}")

    # ── Export paths to parent scope ─────────────────────────────────────────
    string(TOUPPER "${ET_NAME}" _id_upper)
    string(REPLACE "-" "_" _id_upper "${_id_upper}")

    set("EVAL_TARGET_${_id_upper}_SO"  "${_so_path}"  PARENT_SCOPE)
    set("EVAL_TARGET_${_id_upper}_CSV" "${_csv_path}" PARENT_SCOPE)

    # Also store in global properties so define_eval_suite can look them up
    # across different function calls / scopes.
    set_property(GLOBAL PROPERTY "_EVAL_TARGET_${_id_upper}_SO"  "${_so_path}")
    set_property(GLOBAL PROPERTY "_EVAL_TARGET_${_id_upper}_CSV" "${_csv_path}")
endfunction()

# ── define_eval_suite ─────────────────────────────────────────────────────────
# Assembles a named suite from previously defined targets, optionally adding
# obfuscated variants, and writes a suite-level CSV.
#
# Suite CSV format:
#   so_path,targets_csv_path
#   /abs/path/libeval-foo.so,/abs/path/foo.targets.csv
#   ...
#
# Creates CMake target:
#   eval-suite-<suite-id>   – builds all binaries + CSVs for the suite
#
# Exports cache variable:
#   EVAL_SUITE_<SUITE_UPPER>_CSV   – absolute path to the suite CSV
# ─────────────────────────────────────────────────────────────────────────────
function(define_eval_suite)
    cmake_parse_arguments(ES "" "NAME" "TARGETS;OBFUSCATORS" ${ARGN})

    if(NOT ES_NAME OR NOT ES_TARGETS)
        message(FATAL_ERROR "define_eval_suite: NAME and TARGETS are required")
    endif()

    set(_suite_csv "${CMAKE_CURRENT_BINARY_DIR}/${ES_NAME}.targets.csv")
    set(_gen_script "${_EVAL_SCRIPTS_DIR}/generate_suite_csv.py")

    set(_all_dep_targets "")   # CMake target names (for add_custom_target DEPENDS)
    set(_all_dep_files   "")   # Actual file paths (for add_custom_command OUTPUT DEPENDS)
    set(_entry_args "")    # --entry so_path:::csv_path pairs for the Python script

    foreach(_target IN LISTS ES_TARGETS)
        string(TOUPPER "${_target}" _up)
        string(REPLACE "-" "_" _up "${_up}")

        get_property(_so  GLOBAL PROPERTY "_EVAL_TARGET_${_up}_SO")
        get_property(_csv GLOBAL PROPERTY "_EVAL_TARGET_${_up}_CSV")

        if(NOT _so)
            message(FATAL_ERROR "define_eval_suite: target '${_target}' not defined via define_eval_target()")
        endif()

        list(APPEND _all_dep_targets "eval-${_target}-csv")
        list(APPEND _all_dep_files   "${_csv}")
        list(APPEND _entry_args "--entry" "${_so}:::${_csv}")

        # Obfuscated variants
        foreach(_obf IN LISTS ES_OBFUSCATORS)
            get_property(_compiler GLOBAL PROPERTY "_EVAL_OBF_${_obf}_COMPILER")
            if(NOT _compiler OR NOT EXISTS "${_compiler}")
                continue()
            endif()

            get_property(_flags GLOBAL PROPERTY "_EVAL_OBF_${_obf}_FLAGS")
            set(_obf_so   "${CMAKE_CURRENT_BINARY_DIR}/libeval-${_target}-${_obf}.so")
            set(_obf_csv  "${CMAKE_CURRENT_BINARY_DIR}/${_target}-${_obf}.targets.csv")

            # Find the source file from the OBJECT library
            get_target_property(_obj_sources "eval-${_target}-obj" SOURCES)
            list(GET _obj_sources 0 _src_file)
            if(NOT IS_ABSOLUTE "${_src_file}")
                # OBJECT library sources may be relative to their source dir
                get_target_property(_src_dir "eval-${_target}-obj" SOURCE_DIR)
                set(_src_file "${_src_dir}/${_src_file}")
            endif()

            separate_arguments(_flags_list UNIX_COMMAND "${_flags}")

            add_custom_command(
                OUTPUT "${_obf_so}" "${_obf_csv}"
                COMMAND "${_compiler}"
                        ${_flags_list}
                        "${_src_file}"
                        -shared -fPIC -${EVAL_OPT_LEVEL} -fno-stack-protector -fno-tree-vectorize
                        -o "${_obf_so}"
                COMMAND ${Python3_EXECUTABLE} "${_EVAL_SCRIPTS_DIR}/extract_functions.py"
                        --so     "${_obf_so}"
                        --output "${_obf_csv}"
                DEPENDS "${_src_file}"
                COMMENT "[EvalHelpers] Obfuscating ${_target} with ${_obf}"
                VERBATIM
            )

            list(APPEND _all_dep_targets "${_obf_so}")
            list(APPEND _all_dep_files   "${_obf_so}" "${_obf_csv}")
            list(APPEND _entry_args "--entry" "${_obf_so}:::${_obf_csv}")
        endforeach()
    endforeach()

    # ── Suite CSV generation ──────────────────────────────────────────────────
    add_custom_command(
        OUTPUT "${_suite_csv}"
        COMMAND ${Python3_EXECUTABLE} "${_gen_script}"
                --output "${_suite_csv}"
                ${_entry_args}
        DEPENDS ${_all_dep_targets} ${_all_dep_files}
        COMMENT "[EvalHelpers] Generating suite CSV: ${ES_NAME}.targets.csv"
        VERBATIM
    )

    add_custom_target("eval-suite-${ES_NAME}" ALL
        DEPENDS "${_suite_csv}" ${_all_dep_targets}
    )

    # ── Export ────────────────────────────────────────────────────────────────
    string(TOUPPER "${ES_NAME}" _suite_upper)
    string(REPLACE "-" "_" _suite_upper "${_suite_upper}")

    set("EVAL_SUITE_${_suite_upper}_CSV" "${_suite_csv}"
        CACHE STRING "Suite CSV for ${ES_NAME}" FORCE)

    message(STATUS "[EvalHelpers] Suite '${ES_NAME}' defined with ${ES_TARGETS}")
endfunction()
