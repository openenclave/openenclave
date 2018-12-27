# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX OR USE_CLANGW)
set(PLATFORM_SRC
    ../../common/rand.S
    linux/reloc.c
    linux/threadlocal.c
    )
elseif (WIN32)
set(PLATFORM_SRC
    ../../common/rand.asm
    windows/reloc.c
    )
endif()

add_library(oecore STATIC
    ../../common/safecrt.c
    assert.c
    atexit.c
    backtrace.c
    calls.c
    tracee.c
    cpuid.c
    debugmalloc.c
    entropy.c
    exception.c
    globals.c
    hostcalls.c
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
    ${PLATFORM_SRC}
    )

target_link_libraries(oecore PUBLIC oe_includes)

# This directory contains dummy C headers needed by dlmalloc:
target_include_directories(oecore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dlmalloc)

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif ()

# Unfortunately dlmalloc uses GNU extension that allows arithmetic
# null pointers.
set_source_files_properties(
    malloc.c 
    PROPERTIES COMPILE_FLAGS "-Wno-conversion -Wno-null-pointer-arithmetic")

set_source_files_properties(keys.c PROPERTIES COMPILE_FLAGS -Wno-type-limits)

target_compile_options(oecore PUBLIC
    -m64
    -fPIC
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden
    )

target_compile_options(oecore INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

if(USE_LIBSGX)
    target_compile_definitions(oecore PUBLIC OE_USE_LIBSGX)
endif()

if(USE_DEBUG_MALLOC)
    target_compile_definitions(oecore PRIVATE OE_USE_DEBUG_MALLOC)
    message("USE_DEBUG_MALLOC is set, building oecore with memory leak detection.")
endif()

target_compile_definitions(oecore PUBLIC OE_BUILD_ENCLAVE)

# addl link-options for enclave apps
target_link_libraries(oecore INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id)

# jump.s must be optimized for the correct call-frame.
set_source_files_properties(jump.c PROPERTIES COMPILE_FLAGS -O2)

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (WIN32)
    # Mark assembler files for compilation using clang.
    set_source_files_properties(../../common/rand.S  PROPERTIES LANGUAGE C)
    set_source_files_properties(enter.S PROPERTIES LANGUAGE C)
    set_source_files_properties(exit.S PROPERTIES LANGUAGE C)
    set_source_files_properties(getkey.S PROPERTIES LANGUAGE C)
    build_using_clangw(oecore)
endif()
