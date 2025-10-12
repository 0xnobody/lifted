# DownloadRemillDeps.cmake - Download vcpkg dependencies for Remill

function(download_remill_deps CXX_COMMON_VERSION LIBRARY_VERSION DOWNLOAD_DIR)
  set(ARCHIVE_NAME "${LIBRARY_VERSION}.tar.xz")
  set(DOWNLOAD_URL "https://github.com/lifting-bits/cxx-common/releases/download/v${CXX_COMMON_VERSION}/${ARCHIVE_NAME}")
  set(ARCHIVE_PATH "${DOWNLOAD_DIR}/${ARCHIVE_NAME}")
  set(EXTRACT_DIR "${DOWNLOAD_DIR}/${LIBRARY_VERSION}")

  message(STATUS "Downloading dependencies from: ${DOWNLOAD_URL}")
  message(STATUS "Destination: ${DOWNLOAD_DIR}")

  # Create download directory
  file(MAKE_DIRECTORY "${DOWNLOAD_DIR}")

  # Download the archive
  if(NOT EXISTS "${ARCHIVE_PATH}")
    message(STATUS "Fetching ${ARCHIVE_NAME}...")
    file(DOWNLOAD
      "${DOWNLOAD_URL}"
      "${ARCHIVE_PATH}"
      SHOW_PROGRESS
      STATUS DOWNLOAD_STATUS
      TLS_VERIFY ON
    )
    
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    list(GET DOWNLOAD_STATUS 1 STATUS_MESSAGE)
    
    if(NOT STATUS_CODE EQUAL 0)
      message(FATAL_ERROR "Failed to download ${DOWNLOAD_URL}: ${STATUS_MESSAGE}")
    endif()
  else()
    message(STATUS "Archive already exists: ${ARCHIVE_PATH}")
  endif()

  # Extract the archive
  if(NOT EXISTS "${EXTRACT_DIR}")
    message(STATUS "Extracting ${ARCHIVE_NAME}...")
    
    file(MAKE_DIRECTORY "${EXTRACT_DIR}")
    
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E tar xJf "${ARCHIVE_PATH}"
      WORKING_DIRECTORY "${DOWNLOAD_DIR}"
      RESULT_VARIABLE EXTRACT_RESULT
      OUTPUT_VARIABLE EXTRACT_OUTPUT
      ERROR_VARIABLE EXTRACT_ERROR
    )
    
    if(NOT EXTRACT_RESULT EQUAL 0)
      message(FATAL_ERROR "Failed to extract ${ARCHIVE_PATH}: ${EXTRACT_ERROR}")
    endif()
    
    message(STATUS "Successfully extracted to ${EXTRACT_DIR}")
  else()
    message(STATUS "Dependencies already extracted: ${EXTRACT_DIR}")
  endif()

  # Remove the archive to save space
  if(EXISTS "${ARCHIVE_PATH}")
    file(REMOVE "${ARCHIVE_PATH}")
    message(STATUS "Removed archive file to save space")
  endif()

  # Fix modification times to prevent build issues
  message(STATUS "Updating file timestamps...")
  file(GLOB_RECURSE ALL_FILES "${EXTRACT_DIR}/*")
  foreach(FILE_PATH ${ALL_FILES})
    if(EXISTS "${FILE_PATH}")
      file(TOUCH "${FILE_PATH}")
    endif()
  endforeach()

  message(STATUS "Remill dependencies ready at: ${EXTRACT_DIR}")
endfunction()