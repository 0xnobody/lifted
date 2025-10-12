# BootstrapVcpkg.cmake - Bootstrap vcpkg dependencies before project() is called
# This solves the circular dependency by downloading deps first, then using the toolchain

# Configuration
set(VCPKG_LLVM_VERSION "llvm-16" CACHE STRING "LLVM version for vcpkg")
set(VCPKG_CXX_COMMON_VERSION "0.3.1" CACHE STRING "cxx-common version")

function(bootstrap_vcpkg_toolchain)
  message(STATUS "=== Bootstrapping vcpkg ===")
  message(STATUS "Pre-detection info:")
  message(STATUS "  CMAKE_HOST_SYSTEM_NAME: ${CMAKE_HOST_SYSTEM_NAME}")
  message(STATUS "  CMAKE_HOST_SYSTEM_PROCESSOR: ${CMAKE_HOST_SYSTEM_PROCESSOR}")
  
  # Detect platform early
  include(${CMAKE_CURRENT_FUNCTION_LIST_DIR}/DetectPlatform.cmake)
  detect_platform(OS_VERSION ARCH_VERSION VCPKG_TRIPLET)
  
  # Construct library version string
  if(APPLE)
    set(XCODE_VERSION "14.2")
    set(LIBRARY_VERSION "vcpkg_${OS_VERSION}_${VCPKG_LLVM_VERSION}_xcode-${XCODE_VERSION}_${ARCH_VERSION}")
  else()
    set(LIBRARY_VERSION "vcpkg_${OS_VERSION}_${VCPKG_LLVM_VERSION}_${ARCH_VERSION}")
  endif()
  
  set(DOWNLOAD_DIR "${CMAKE_CURRENT_BINARY_DIR}/downloads/lifting-bits-downloads")
  set(VCPKG_ROOT "${DOWNLOAD_DIR}/${LIBRARY_VERSION}")
  set(VCPKG_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
  
  message(STATUS "Detected platform: ${OS_VERSION} ${ARCH_VERSION}")
  message(STATUS "Library Version: ${LIBRARY_VERSION}")
  message(STATUS "vcpkg Triplet: ${VCPKG_TRIPLET}")
  
  # Download if not present
  if(NOT EXISTS "${VCPKG_ROOT}")
    message(STATUS "Downloading vcpkg dependencies (this may take a few minutes)...")
    include(${CMAKE_CURRENT_FUNCTION_LIST_DIR}/DownloadRemillDeps.cmake)
    download_remill_deps(
      "${VCPKG_CXX_COMMON_VERSION}"
      "${LIBRARY_VERSION}"
      "${DOWNLOAD_DIR}"
    )
  else()
    message(STATUS "vcpkg dependencies found at: ${VCPKG_ROOT}")
  endif()
  
  # Verify toolchain exists
  if(NOT EXISTS "${VCPKG_TOOLCHAIN_FILE}")
    message(FATAL_ERROR "vcpkg toolchain not found at: ${VCPKG_TOOLCHAIN_FILE}")
  endif()
  
  # Set toolchain file for this project and all subdirectories
  set(CMAKE_TOOLCHAIN_FILE "${VCPKG_TOOLCHAIN_FILE}" CACHE FILEPATH "vcpkg toolchain file" FORCE)
  set(VCPKG_TARGET_TRIPLET "${VCPKG_TRIPLET}" CACHE STRING "vcpkg target triplet" FORCE)
  
  # Export variables for use by other modules
  set(VCPKG_ROOT "${VCPKG_ROOT}" CACHE PATH "vcpkg root directory" FORCE)
  set(VCPKG_INSTALLED_DIR "${VCPKG_ROOT}/installed" CACHE PATH "vcpkg installed directory" FORCE)
  
  message(STATUS "vcpkg toolchain configured: ${VCPKG_TOOLCHAIN_FILE}")
  message(STATUS "=== vcpkg bootstrap complete ===")
  message(STATUS "")
endfunction()
