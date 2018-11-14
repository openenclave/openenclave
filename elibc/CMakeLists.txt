# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(UNIX)
    set(SOURCES setjmp.S longjmp.S)
elseif (WIN32)
    # Put windows setjmp.asm and longjmp.asm here
endif()


add_library(oeelibc STATIC
    assert.c
    atexit.c
    ctype.c
    errno.c
    gmtime.c
    intstr.c
    malloc.c
    printf.c
    pthread.c
    rand.c
    sbrk.c
    stdio.c
    strerror.c
    string.c
    strtoul.c
    time.c
    ${SOURCES})

target_link_libraries(oeelibc oecore)

target_compile_options(oeelibc INTERFACE -nostdinc)

target_include_directories(oeelibc PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/openenclave/elibc)

set_property(TARGET oeelibc
    PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeelibc
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
