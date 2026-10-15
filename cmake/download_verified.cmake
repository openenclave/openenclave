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
  foreach (attempt RANGE 1 3)
    file(
      DOWNLOAD "${url}" "${temporary}"
      STATUS status
      TIMEOUT 120
      INACTIVITY_TIMEOUT 30
      TLS_VERIFY ON)
    list(GET status 0 code)
    if (code EQUAL 0)
      file(SHA256 "${temporary}" actual)
      if (NOT actual STREQUAL sha256)
        file(REMOVE "${temporary}")
        message(FATAL_ERROR "SHA256 mismatch downloading ${url}")
      endif ()
      file(RENAME "${temporary}" "${destination}")
      return()
    endif ()
    file(REMOVE "${temporary}")
    message(STATUS "Download attempt ${attempt}/3 failed for ${url}: ${status}")
  endforeach ()
  message(FATAL_ERROR "Failed to download ${url} after 3 attempts: ${status}")
endfunction ()
