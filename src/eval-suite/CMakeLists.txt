project(eval-suite)

add_library(eval-suite STATIC
    suite.hpp
    suite.cpp
    eval_pipeline.hpp
    eval_pipeline.cpp
)

target_include_directories(eval-suite PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(eval-suite PUBLIC lifted)

# Inject compile-time CSV paths so resolve_suite_name() / known_suite_names()
# can map names to paths.  Each definition is conditional in the source via
# #ifdef so the library compiles cleanly even when a suite is absent.
target_compile_definitions(eval-suite PRIVATE
    "EVAL_SUITE_SYNTHETIC_CSV=\"${EVAL_SUITE_SYNTHETIC_CSV}\""
    "EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV=\"${EVAL_SUITE_TUM_SMALL_PROGRAMS_CSV}\""
    "EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV=\"${EVAL_SUITE_TUM_BASIC_ALGORITHMS_CSV}\""
    "EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV=\"${EVAL_SUITE_TUM_SIMPLE_HASH_FUNCTIONS_CSV}\""
    "EVAL_SUITE_GNU_COREUTILS_CSV=\"${EVAL_SUITE_GNU_COREUTILS_CSV}\""
)

# Must be built after the suite targets so .so files + CSVs exist at link time.
foreach(suite_target IN ITEMS
    eval-suite-synthetic
    eval-suite-tum-small-programs
    eval-suite-tum-basic-algorithms
    eval-suite-tum-simple-hash-functions
    eval-suite-gnu-coreutils)
  if(TARGET ${suite_target})
    add_dependencies(eval-suite ${suite_target})
  endif()
endforeach()
