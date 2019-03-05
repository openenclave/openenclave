# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(configure_host TARGET)
    target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(${TARGET} oestdio_host oesocket_host oehost)

    if(UNIX)
        add_dependencies(${TARGET} oeedger8rtool)

        target_compile_definitions(${TARGET} PUBLIC LINUX)
        target_link_libraries(${TARGET} teec)
    elseif(WIN32 AND TZ AND SIM)
        target_link_libraries(${TARGET} oehost_opteesim)
    endif()

    if(SGX)
        target_compile_definitions(${TARGET} PUBLIC OE_USE_SGX)
    else()
        if(SIM)
            target_compile_definitions(${TARGET} PUBLIC OE_SIMULATE_OPTEE)
        else()
            target_compile_definitions(${TARGET} PUBLIC OE_USE_OPTEE)
        endif()
    endif()
endfunction()

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

    configure_host(${HOST_TARGET})
endfunction()
