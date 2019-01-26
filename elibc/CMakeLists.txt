# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeelibc STATIC
    atexit.c
    gmtime.c
    intstr.c
    malloc.c
    printf.c
    pthread.c
    rand.c
    stdio.c
    strtoul.c
    time.c
    ${SOURCES})

maybe_build_using_clangw(oeelibc)

target_link_libraries(oeelibc oecore)

target_compile_options(oeelibc INTERFACE -nostdinc)

target_include_directories(oeelibc PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/openenclave/elibc)

set_property(TARGET oeelibc
    PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeelibc EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
