# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(IS_JAMMY FALSE)

if (UNIX)
  set(OS_INFO "")
  file(READ "/etc/os-release" OS_INFO)
  if (OS_INFO STREQUAL "")
    message(FATAL_ERROR "Failed to read /etc/os-release")
  endif ()
  set(STRPOS -1)
  string(FIND "${OS_INFO}" "UBUNTU_CODENAME=jammy" STRPOS)
  if (NOT STRPOS EQUAL -1)
    set(IS_JAMMY TRUE)
  endif ()
endif ()

if (NOT IS_JAMMY)
  add_subdirectory(oeapkman)
endif ()

if (OE_SGX)
  add_subdirectory(oecertdump)
  add_subdirectory(oesign)
  add_subdirectory(oeseal)
endif ()
