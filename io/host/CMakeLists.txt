# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(EDL_DIR ${CMAKE_SOURCE_DIR}/io/edl)
set(EDL_FILE ${EDL_DIR}/oeio.edl)

add_custom_command(
    OUTPUT oeio_u.h oeio_u.c oeio_args.h
    DEPENDS ${EDL_FILE}
    COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${EDL_FILE})

add_custom_target(oeio_untrusted_edl DEPENDS oeio_u.h oeio_u.c oeio_args.h)

if(UNIX)
    set(PLATFORM_DIR linux)
elseif(WIN32)
    set(PLATFORM_DIR windows)
else()
    message(FATAL_ERROR "unknown platform")
endif()

add_library(oeiohost STATIC
    oeio_u_wrapper.c
    ${PLATFORM_DIR}/oeio.c)

if(UNIX)
    target_compile_definitions(oeiohost PRIVATE _GNU_SOURCE)
endif()

add_dependencies(oeiohost oeio_untrusted_edl)

target_include_directories(oeiohost PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeiohost oehostapp)
