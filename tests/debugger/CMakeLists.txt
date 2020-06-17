# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
if (BUILD_TYPE_UPPER STREQUAL "DEBUG" OR BUILD_TYPE_UPPER STREQUAL
                                         "RELWITHDEBINFO")
  if (UNIX)
    add_subdirectory(oegdb)
  endif ()
endif ()
