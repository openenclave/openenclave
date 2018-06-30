# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecore STATIC
    corelibc/errno.c
    corelibc/gmtime.c
    corelibc/malloc.c
    corelibc/printf.c
    corelibc/rand.c
    corelibc/sbrk.c
    corelibc/stdio.c
    corelibc/string.c
    corelibc/strtoul.c
    corelibc/time.c
    assert.c
    atexit.c
    calls.c
    cpuid.c
    entropy.c
    exception.c
    globals.c
    hostcalls.c
    hoststack.c
    hexdump.c
    init.c
    intstr.c
    jump.c
    keys.c
    memory.c
    once.c
    result.c
    report.c
    spinlock.c
    td.c
    thread.c
    exit.S
    getkey.S
    main.S)

set_source_files_properties(corelibc/malloc.c corelibc/time.c PROPERTIES COMPILE_FLAGS
    -I"${PROJECT_SOURCE_DIR}/include/openenclave/internal/corelibc")

target_link_libraries(oecore PUBLIC oe_includes)

# we strip the default include containing the compiler-provided intrinsics
# add it back in
target_include_directories(oecore SYSTEM PRIVATE ${OE_C_COMPILER_INCDIR})

target_compile_options(oecore PUBLIC
    -m64 -fPIC
    -nostdinc
    $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
    -fno-stack-protector -fvisibility=hidden
    )

if(USE_LIBSGX)
target_compile_definitions(oecore PUBLIC OE_USE_LIBSGX)
endif()

target_compile_definitions(oecore PUBLIC OE_BUILD_ENCLAVE)

# addl link-options for enclave apps
target_link_libraries(oecore INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,-eoe_main
    )

# jump.s must be optimized for the correct call-frame.
set_source_files_properties(jump.c PROPERTIES COMPILE_FLAGS -O2)

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
