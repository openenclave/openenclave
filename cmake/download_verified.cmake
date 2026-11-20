# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Publish only verified bytes, retaining the cache across transient HTTP errors.
function (oe_download_verified url destination sha256)
  if (EXISTS "${destination}")
    file(SHA256 "${destination}" actual)
    if (actual STREQUAL sha256)
      return()
    endif ()
  endif ()

  get_filename_component(directory "${destination}" DIRECTORY)
  file(MAKE_DIRECTORY "${directory}")
  set(temporary "${destination}.download")
  # Optional upstream mirrors must serve exactly the same pinned bytes.
  set(urls "${url}" ${ARGN})
  foreach (attempt RANGE 1 3)
    foreach (source_url IN LISTS urls)
      file(
        DOWNLOAD "${source_url}" "${temporary}"
        STATUS status
        LOG transfer_log
        TIMEOUT 120
        INACTIVITY_TIMEOUT 30
        TLS_VERIFY ON)
      list(GET status 0 code)
      if (code EQUAL 0)
        file(SHA256 "${temporary}" actual)
        if (NOT actual STREQUAL sha256)
          file(REMOVE "${temporary}")
          message(FATAL_ERROR "SHA256 mismatch downloading ${source_url}")
        endif ()
        file(RENAME "${temporary}" "${destination}")
        return()
      endif ()
      file(REMOVE "${temporary}")
      # Emit only HTTP status lines, never proxy credentials or response headers.
      string(REGEX MATCHALL "HTTP/[0-9.]+ +[0-9][0-9][0-9]" http_status
                   "${transfer_log}")
      if (NOT http_status)
        set(http_status "no HTTP response received")
      endif ()
      message(
        STATUS
          "Download attempt ${attempt}/3 failed for ${source_url}: ${status}; ${http_status}"
      )
    endforeach ()
  endforeach ()
  message(
    FATAL_ERROR
      "Failed to download ${url} after 3 attempts: ${status}; ${http_status}")
endfunction ()
