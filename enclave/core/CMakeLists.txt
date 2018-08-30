# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_compile_flags_if_supported)
include(add_compile_defs)

add_library(oecore STATIC
    assert.c
    atexit.c
    backtrace.c
    calls.c
    cpuid.c
    debugmalloc.c
    entropy.c
    exception.c
    globals.c
    hostcalls.c
    hoststack.c
    hexdump.c
    init.c
    jump.c
    keys.c
    malloc.c
    memory.c
    once.c
    properties.c
    result.c
    report.c
    sbrk.c
    snprintf.c
    spinlock.c
    string.c
    td.c
    thread.c
    time.c
    enter.S
    exit.S
    getkey.S
    )

target_link_libraries(oecore PUBLIC oe_includes)

# we strip the default include containing the compiler-provided intrinsics
# add it back in
target_include_directories(oecore SYSTEM PRIVATE ${OE_C_COMPILER_INCDIR})

# This directory contains dummy C headers needed by dlmalloc:
target_include_directories(oecore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dlmalloc)

add_target_compile_flags(oecore PUBLIC "C;CXX"
    -m64
    -fPIC
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden
    )

add_target_compile_flags(oecore PUBLIC CXX
    -nostdinc++
    )

if(USE_LIBSGX)
    add_target_compile_defs(oecore PUBLIC "C;CXX" OE_USE_LIBSGX)
endif()

if(USE_DEBUG_MALLOC)
    add_target_compile_defs(oecore PRIVATE "C;CXX" OE_USE_DEBUG_MALLOC)
endif()

add_target_compile_defs(oecore PUBLIC "C;CXX" OE_BUILD_ENCLAVE)

# addl link-options for enclave apps
target_link_libraries(oecore INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie)

# jump.s must be optimized for the correct call-frame.
set_source_files_properties(jump.c PROPERTIES COMPILE_FLAGS -O2)

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
