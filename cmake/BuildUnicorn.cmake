# BuildUnicorn.cmake - Fetch and build Unicorn Engine using ExternalProject_Add

message(STATUS "=== Fetching and Configuring Unicorn Engine ===")

include(ExternalProject)

# Configuration options
set(UNICORN_VERSION "2.1.4" CACHE STRING "Unicorn Engine version/tag to fetch")
set(UNICORN_REPOSITORY "https://github.com/unicorn-engine/unicorn.git" CACHE STRING "Unicorn Engine repository URL")

# Preferred source/build locations
set(UNICORN_SOURCE_DIR "${CMAKE_SOURCE_DIR}/external/unicorn")
set(UNICORN_BINARY_DIR "${CMAKE_BINARY_DIR}/unicorn-build")
set(UNICORN_INSTALL_DIR "${CMAKE_BINARY_DIR}/unicorn-install")

ExternalProject_Add(unicorn
  GIT_REPOSITORY        ${UNICORN_REPOSITORY}
  GIT_TAG               ${UNICORN_VERSION}
  SOURCE_DIR            ${UNICORN_SOURCE_DIR}
  BINARY_DIR            ${UNICORN_BINARY_DIR}
  CMAKE_GENERATOR       "Ninja"

  # Drive configuration purely via CMake arguments
  CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX=${UNICORN_INSTALL_DIR}
    -DUNICORN_ARCH=x86
    -DBUILD_SHARED_LIBS=ON

  # Quality-of-life options
  UPDATE_DISCONNECTED 1
  LOG_CONFIGURE 1
  LOG_BUILD 1
  LOG_INSTALL 1
)

# Interface target other targets can depend on
add_library(unicorn_external INTERFACE)
add_dependencies(unicorn_external unicorn)

target_include_directories(unicorn_external INTERFACE
  "${UNICORN_INSTALL_DIR}/include"
)

target_link_directories(unicorn_external INTERFACE
  "${UNICORN_INSTALL_DIR}/lib"
)

target_link_libraries(unicorn_external INTERFACE
  unicorn
)

set(UNICORN_INCLUDE_DIR "${UNICORN_INSTALL_DIR}/include" CACHE PATH "Path to Unicorn Engine include directory")
set(UNICORN_LIBRARY "${UNICORN_INSTALL_DIR}/lib/libunicorn.so" CACHE FILEPATH "Path to Unicorn Engine library")

message(STATUS "=== UNICORN configuration complete ===")
message(STATUS "")
