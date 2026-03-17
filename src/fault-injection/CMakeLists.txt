project(fault-injection)

add_library(fault-injection STATIC
    ir_mutation.hpp
    mutation_operators.hpp
    mutation_operators.cpp
    mutation_point.hpp
    mutation_enumeration.hpp
    mutation_enumeration.cpp
    mutation_campaign.hpp
    mutation_campaign.cpp
)

# fault-injection is a consumer of 'lifted'; all of src/lifted/ is PUBLIC in
# the 'lifted' target so our headers can include verification/, pipeline/, etc.
target_link_libraries(fault-injection PUBLIC lifted)

# Expose src/fault-injection/ as public include root so consumers can do:
#   #include "mutation_campaign.hpp"
target_include_directories(fault-injection PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
