cmake_minimum_required(VERSION 3.21)

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE PATH "Install prefix" FORCE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Bootstrap vcpkg (BEFORE project!)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  include(BootstrapVcpkg)
  bootstrap_vcpkg_toolchain()
endif()

project(MyProject)

# FetchContent will download these automatically
include(BuildRemill)
include(BuildKLEE)

# Your code
add_executable(my_app src/main.cpp)

target_link_libraries(my_app PRIVATE remill klee)