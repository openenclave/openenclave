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
        target_compile_definitions(${HOST_TARGET} PUBLIC LINUX)
        target_link_libraries(${HOST_TARGET} teec)
    elseif(WIN32 AND TZ AND SIM)
        target_link_libraries(${HOST_TARGET} oehost_opteesim)
    endif()

    if(SGX)
        target_compile_definitions(${HOST_TARGET} PUBLIC OE_USE_SGX)
    else()
        if(SIM)
            target_compile_definitions(${HOST_TARGET} PUBLIC OE_SIMULATE_OPTEE)
        else()
            target_compile_definitions(${HOST_TARGET} PUBLIC OE_USE_OPTEE)
        endif()
    endif()
endfunction()
