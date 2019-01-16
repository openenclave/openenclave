# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(add_host)
    # Borrowed from ../cmake/add_enclave.cmake
    # Using the same signature so that the functions are easier to merge.
    set(options CXX)
    set(oneValueArgs TARGET)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(HOST
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    add_executable(${HOST_TARGET} ${HOST_SOURCES})

    target_include_directories(${HOST_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${HOST_TARGET} oehost oestdio_host oesocket_host)

    if(UNIX)
        target_link_libraries(${HOST_TARGET} teec)
    elseif(WIN32 AND TZ AND SIM)
        target_link_libraries(${HOST_TARGET} oehost_opteesim)
    endif()
endfunction()
