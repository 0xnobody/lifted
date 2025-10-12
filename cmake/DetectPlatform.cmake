# DetectPlatform.cmake - Detect OS version and architecture for Remill builds

function(detect_platform OUT_OS_VERSION OUT_ARCH_VERSION OUT_VCPKG_TRIPLET)
  # Detect architecture using uname since CMAKE_SYSTEM_PROCESSOR may not be set before project()
  if(WIN32)
    # Windows - use environment variable
    set(MACHINE "$ENV{PROCESSOR_ARCHITECTURE}")
  else()
    # Unix-like systems - use uname
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE MACHINE
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
  endif()
  
  # Fallback to CMAKE_SYSTEM_PROCESSOR if uname failed
  if(NOT MACHINE)
    set(MACHINE "${CMAKE_SYSTEM_PROCESSOR}")
  endif()
  
  # Map architecture
  if(MACHINE MATCHES "x86_64|AMD64|amd64|x86-64")
    set(ARCH "amd64")
    set(VCPKG_ARCH "x64")
  elseif(MACHINE MATCHES "aarch64|arm64|ARM64")
    set(ARCH "arm64")
    set(VCPKG_ARCH "arm64")
  else()
    message(FATAL_ERROR "Unsupported architecture: '${MACHINE}'. Only x86_64 and aarch64 are supported.\nDetection info:\n  uname -m output: '${MACHINE}'\n  CMAKE_SYSTEM_PROCESSOR: '${CMAKE_SYSTEM_PROCESSOR}'\n  CMAKE_HOST_SYSTEM_PROCESSOR: '${CMAKE_HOST_SYSTEM_PROCESSOR}'")
  endif()

  # Detect OS - also need to handle this before project()
  if(APPLE)
    # macOS detection
    execute_process(
      COMMAND sw_vers -productVersion
      OUTPUT_VARIABLE MACOS_VERSION
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    
    if(MACOS_VERSION MATCHES "^13\\.")
      set(OS "macos-12")
      message(STATUS "Detected macOS Ventura (using macos-12 libraries)")
    elseif(MACOS_VERSION MATCHES "^12\\.")
      set(OS "macos-12")
      message(STATUS "Detected macOS Monterey")
    else()
      set(OS "macos-12")
      message(WARNING "macOS version ${MACOS_VERSION} may not be fully supported. Using macos-12 libraries.")
    endif()
    
    set(VCPKG_TRIPLET "${VCPKG_ARCH}-osx-rel")
    
  elseif(UNIX)
    # Linux detection - CMAKE_SYSTEM_NAME might not be set, so check for Unix-like
    set(IS_LINUX FALSE)
    
    # Try to detect if we're on Linux
    if(EXISTS "/etc/os-release")
      set(IS_LINUX TRUE)
    elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
      set(IS_LINUX TRUE)
    endif()
    
    if(IS_LINUX)
      file(READ "/etc/os-release" OS_RELEASE)
      
      # Extract ID
      string(REGEX MATCH "ID=([a-zA-Z0-9_]+)" _ ${OS_RELEASE})
      set(DISTRO_ID "${CMAKE_MATCH_1}")
      string(TOLOWER "${DISTRO_ID}" DISTRO_ID)
      
      if(DISTRO_ID MATCHES "ubuntu")
        # Extract version codename
        string(REGEX MATCH "VERSION_CODENAME=([a-z]+)" _ ${OS_RELEASE})
        set(CODENAME "${CMAKE_MATCH_1}")
        
        if(CODENAME STREQUAL "jammy")
          set(OS "ubuntu-22.04")
        elseif(CODENAME STREQUAL "kinetic")
          set(OS "ubuntu-22.04")
          message(STATUS "Ubuntu 22.10 detected, using Ubuntu 22.04 libraries")
        elseif(CODENAME STREQUAL "lunar")
          set(OS "ubuntu-22.04")
          message(STATUS "Ubuntu 23.04 detected, using Ubuntu 22.04 libraries")
        else()
          message(WARNING "Ubuntu ${CODENAME} may not be supported. Only jammy (22.04) is officially supported. Using Ubuntu 22.04 libraries.")
          set(OS "ubuntu-22.04")
        endif()
      elseif(DISTRO_ID MATCHES "debian|arch|kali")
        set(OS "ubuntu-22.04")
        message(STATUS "Detected ${DISTRO_ID}, using Ubuntu 22.04 libraries")
      else()
        message(WARNING "${DISTRO_ID} is not officially supported. Using Ubuntu 22.04 libraries.")
        set(OS "ubuntu-22.04")
      endif()
    else()
      message(WARNING "Cannot detect Linux distribution. Using Ubuntu 22.04 libraries.")
      set(OS "ubuntu-22.04")
    endif()
    
    set(VCPKG_TRIPLET "${VCPKG_ARCH}-linux-rel")
    
  else()
    message(FATAL_ERROR "Unsupported operating system. Only macOS and Linux are supported.")
  endif()

  # Set output variables
  set(${OUT_OS_VERSION} "${OS}" PARENT_SCOPE)
  set(${OUT_ARCH_VERSION} "${ARCH}" PARENT_SCOPE)
  set(${OUT_VCPKG_TRIPLET} "${VCPKG_TRIPLET}" PARENT_SCOPE)
endfunction()