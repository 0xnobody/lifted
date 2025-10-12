# cmake/klee_wrapper.cmake
# This runs inside KLEE's own CMake configuration
if (PROJECT_NAME STREQUAL "KLEE")
  # Redirect its mistaken assumptions
  set(CMAKE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE INTERNAL "" FORCE)
  set(CMAKE_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}" CACHE INTERNAL "" FORCE)
endif()
