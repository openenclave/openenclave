# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(PLATFORM_SRC "")
set(MUSL_SRC_DIR ${PROJECT_SOURCE_DIR}/3rdparty/musl/musl/src)

if (OE_SGX)
    list(APPEND PLATFORM_SRC
        sgx/atexit.c
        sgx/backtrace.c
        sgx/calls.c
        sgx/cpuid.c
        sgx/debugmalloc.c
        sgx/entropy.c
        sgx/errno.c
        sgx/exception.c
        sgx/globals.c
        sgx/hostcalls.c
        sgx/init.c
        sgx/jump.c
        sgx/keys.c
        sgx/malloc.c
        sgx/memory.c
        sgx/once.c
        sgx/properties.c
        sgx/report.c
        sgx/sbrk.c
        sgx/sched_yield.c
        sgx/spinlock.c
        sgx/td.c
        sgx/thread.c
        sgx/tracee.c
        sgx/enter.S
        sgx/exit.S
        sgx/getkey.S
        sgx/longjmp.S
        sgx/setjmp.S)

    # OS specific sources for SGX.
    if (UNIX OR USE_CLANGW)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.S
            sgx/linux/reloc.c
            sgx/linux/threadlocal.c)
    elseif (WIN32)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.asm
            sgx/windows/reloc.c)
    endif()
elseif(OE_TRUSTZONE)
    message("TODO: ADD ARM files.")
    list(APPEND PLATFORM_SRC
        optee/abort.c
        optee/bounds.c
        optee/host.c
        optee/printf.c
        optee/sched_yield.c
        optee/start.c)
endif()

add_library(oecore STATIC
    ../../common/safecrt.c
    ${MUSL_SRC_DIR}/prng/rand.c
    ${MUSL_SRC_DIR}/string/memcmp.c
    ${MUSL_SRC_DIR}/string/memcpy.c
    ${MUSL_SRC_DIR}/string/memmove.c
    ${MUSL_SRC_DIR}/string/memset.c
    __secs_to_tm.c
    __stack_chk_fail.c
    assert.c
    ctype.c
    gmtime.c
    hexdump.c
    intstr.c
    printf.c
    pthread.c
    result.c
    stdio.c
    strerror.c
    string.c
    strtoul.c
    time.c
    ${PLATFORM_SRC})

# Suppress type conversion warnings introduced by 3rdparty code
set_source_files_properties(${MUSL_SRC_DIR}/prng/rand.c ROPERTIES
    COMPILE_FLAGS -Wno-conversion)
set_source_files_properties(${MUSL_SRC_DIR}/string/memset.c PROPERTIES
    COMPILE_FLAGS -Wno-conversion)
set_source_files_properties(__secs_to_tm.c PROPERTIES
    COMPILE_FLAGS -Wno-conversion)

maybe_build_using_clangw(oecore)

target_link_libraries(oecore PUBLIC oe_includes)

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif()

# This directory contains enclave core libc headers:
target_include_directories(oecore PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

if (OE_SGX)
    # Unfortunately dlmalloc uses GNU extension that allows arithmetic
    # null pointers.
    set_source_files_properties(sgx/malloc.c
        PROPERTIES COMPILE_FLAGS "-Wno-conversion -Wno-null-pointer-arithmetic")

    # jump.s must be optimized for the correct call-frame.
    set_source_files_properties(sgx/jump.c PROPERTIES COMPILE_FLAGS -O2)

    set_source_files_properties(sgx/keys.c PROPERTIES COMPILE_FLAGS -Wno-type-limits)

    # -m64 is an x86_64 specific flag
    target_compile_options(oecore PUBLIC -m64)
endif()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif ()

target_compile_options(oecore PUBLIC
    -fPIC
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden)

target_compile_options(oecore INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

target_compile_definitions(oecore
    PUBLIC
    OE_BUILD_ENCLAVE
    OE_API_VERSION=2)

if(USE_LIBSGX)
    target_compile_definitions(oecore PUBLIC OE_USE_LIBSGX)
endif()

if(USE_DEBUG_MALLOC)
    target_compile_definitions(oecore PRIVATE OE_USE_DEBUG_MALLOC)
    message("USE_DEBUG_MALLOC is set, building oecore with memory leak detection.")
endif()

# addl link-options for enclave apps
target_link_libraries(oecore INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id)

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
