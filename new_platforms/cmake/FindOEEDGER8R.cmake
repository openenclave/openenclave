# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(UNIX)
    set(OEEDGER8R_NAME oeedger8r)
elseif(WIN32)
    set(OEEDGER8R_NAME oeedger8r.exe)
endif()

set(OEEDGER8R_URI_PREFIX https://oedownload.blob.core.windows.net/binaries/master/85/oeedger8r/build/output/bin)
set(OEEDGER8R_URI ${OEEDGER8R_URI_PREFIX}/${OEEDGER8R_NAME})

find_program(OEEDGER8R_PATH ${OEEDGER8R_NAME})

if(NOT OEEDGER8R_PATH)
    set(OEEDGER8R_PATH ${CMAKE_BINARY_DIR}/${OEEDGER8R_NAME})

    if(NOT EXISTS ${OEEDGER8R_PATH})
        message(STATUS "Downloading OEEDGER8R...")
        file(DOWNLOAD ${OEEDGER8R_URI} ${OEEDGER8R_PATH})
        message(STATUS "  OK")
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OEEDGER8R REQUIRED_VARS OEEDGER8R_PATH)
