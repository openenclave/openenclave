# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(PLATFORM_SRC "")
set(MUSL_SRC_DIR ${PROJECT_SOURCE_DIR}/3rdparty/musl/musl/src)

if (OE_SGX)
    list(APPEND PLATFORM_SRC
        sgx/atexit.c
        sgx/backtrace.c
        sgx/calls.c
        sgx/console.c
        sgx/cpuid.c
        sgx/debugmalloc.c
        sgx/entropy.c
        sgx/errno.c
        sgx/exception.c
        sgx/globals.c
        sgx/globals.c
        sgx/hostbatch.c
        sgx/hostcalls.c
        sgx/hostfs.c
        sgx/hostsock.c
        sgx/epoll.c
        sgx/eventfd.c
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
        optee/errno.c
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
    array.c
    assert.c
    corelibc.c
    ctype.c
    cwd.c
    device.c
    epoll.c
    exit.c
    select.c
    poll.c
    eventfd.c
    fd.c
    fs.c
    gethostname.c
    getdomainname.c
    gmtime.c
    hexdump.c
    intstr.c
    mount.c
    printf.c
    pthread.c
    realpath.c
    resolver.c
    result.c
    sleep.c
    socket.c
    stdio.c
    strerror.c
    strcspn.c
    string.c
    strspn.c
    strtok_r.c
    strchrnul.c
    strtoul.c
    syscall.c
    time.c
    uname.c
    ${PLATFORM_SRC})

# Suppress type conversion warnings introduced by 3rdparty code
set_source_files_properties(${MUSL_SRC_DIR}/prng/rand.c ROPERTIES
    COMPILE_FLAGS -Wno-conversion)
set_source_files_properties(${MUSL_SRC_DIR}/string/memmove.c PROPERTIES
    COMPILE_FLAGS -Wno-sign-conversion)
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

target_include_directories(oecore PRIVATE
    ${PROJECT_SOURCE_DIR}/enclave/core/include)

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

# NOTE: All code inside an enclave must be compile with "position
# independent executable" semantics via -fPIE, and linked with -pie.
# Hence the PUBLIC (and INTERFACE) use of these flags instead of -fPIC
# or POSITION_INDEPENDENT_CODE, which would use the incorrect flag as
# enclaves actually are executables.
target_compile_options(oecore PUBLIC
    -fPIE
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden)

target_compile_options(oecore INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

target_compile_definitions(oecore
    PUBLIC
    OE_BUILD_ENCLAVE
    # NOTE: This definition is public to the rest of our project's
    # targets, but should not yet be exposed to consumers of our
    # package.
    $<BUILD_INTERFACE:OE_API_VERSION=2>)

if(USE_LIBSGX)
    target_compile_definitions(oecore PUBLIC OE_USE_LIBSGX)
endif()

if(USE_DEBUG_MALLOC)
    target_compile_definitions(oecore PRIVATE OE_USE_DEBUG_MALLOC)
    message("USE_DEBUG_MALLOC is set, building oecore with memory leak detection.")
endif()

# Interface link flags for enclaves.
target_link_libraries(oecore INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id)

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
