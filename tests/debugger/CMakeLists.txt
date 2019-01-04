# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
if (BUILD_TYPE_UPPER STREQUAL "DEBUG" OR BUILD_TYPE_UPPER STREQUAL "RELWITHDEBINFO")
    if (UNIX)
        add_subdirectory(oe-gdb)
    endif()
endif()
