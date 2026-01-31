project("lifter-eval-synthetic")

function(set_optimized_target target_name)
    add_library(eval-${target_name} SHARED ${target_name}.cpp)
    target_compile_options(eval-${target_name} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-O2 -DNDEBUG>
        $<$<CXX_COMPILER_ID:MSVC>:/O2 /DNDEBUG>
        -fno-stack-protector
        -fno-tree-vectorize
    )
endfunction()

function(set_polaris_target)
    set(POLARIS_OUTPUTS "")
    set(POLARIS_INPUTS "")

    foreach(target ${ARGN})
        set(so "${CMAKE_CURRENT_BINARY_DIR}/libeval-${target}-polaris.so")
        set(source "${CMAKE_CURRENT_LIST_DIR}/${target}.cpp")

        add_custom_command(
            OUTPUT ${so}
            COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
            COMMAND "${POLARIS_CLANG_PATH}" -mllvm -passes="${POLARIS_PASSES}" "${source}" -shared -fPIC -o "${so}"
            DEPENDS ${source}
            COMMENT "Compiling Polaris binary: ${source}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        )
        list(APPEND POLARIS_OUTPUTS ${so})
        list(APPEND POLARIS_INPUTS ${source})
    endforeach()

    add_custom_target(eval-polaris-bins ALL
        DEPENDS ${POLARIS_OUTPUTS}
        SOURCES ${POLARIS_INPUTS}
    )

    add_dependencies(eval-polaris-bins polaris_external)
endfunction()

# List of all synthetic evaluation libraries
set(EVAL_SYNTHETIC_LIBS
    arithmetic
    branch
    ext-call-branching
    ext-call
    indirect-call
    local-vars
    loop-bounded
    loop-unbounded
    stack-args
    stack-loop
    switch
    test
    ext-call-stack-args
)

foreach(lib ${EVAL_SYNTHETIC_LIBS})
    set_optimized_target(${lib})
endforeach()

set_polaris_target(${EVAL_SYNTHETIC_LIBS})

set(EVAL_SYNTHETIC_LIBS_DIR "${CMAKE_BINARY_DIR}/src/evaluation/synthetic" CACHE STRING "Directory containing synthetic evaluation shared libraries")