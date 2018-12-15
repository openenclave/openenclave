# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
    set(PLATFORM_SRC
        sgx/atexit.c
        sgx/backtrace.c
        sgx/calls.c
        sgx/tracee.c
        sgx/cpuid.c
        sgx/debugmalloc.c
        sgx/entropy.c
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
        sgx/spinlock.c
        sgx/td.c
        sgx/thread.c
        sgx/enter.S
        sgx/exit.S
        sgx/getkey.S
    )

    # OS specific sources for SGX.
    if (UNIX)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.S
            sgx/linux/reloc.c
            sgx/linux/threadlocal.c
        )
    elseif (WIN32)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.asm
            sgx/windows/reloc.c
        )
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
    message("TODO: ADD ARM files.")
    list(APPEND PLATFORM_SRC
        optee/abort.c
        optee/bounds.c
        optee/printf.c
        )
else()
    message(FATAL_ERROR "Unknown architecture. Only Intel and ARM are supported.")
endif()

add_library(oecore STATIC
    ../../common/safecrt.c
    assert.c
    hexdump.c
    result.c
    snprintf.c
    string.c
    time.c
    ${PLATFORM_SRC}
)

target_link_libraries(oecore PUBLIC oe_includes)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
    # This directory contains dummy C headers needed by dlmalloc:
    target_include_directories(oecore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/sgx/dlmalloc)

    # Unfortunately dlmalloc uses GNU extension that allows arithmetic
    # null pointers.
    set_source_files_properties(sgx/malloc.c
        PROPERTIES COMPILE_FLAGS "-Wno-conversion -Wno-null-pointer-arithmetic")
    
    # jump.s must be optimized for the correct call-frame.
    set_source_files_properties(sgx/jump.c PROPERTIES COMPILE_FLAGS -O2)

    set_source_files_properties(sgx/keys.c PROPERTIES COMPILE_FLAGS -Wno-type-limits)
endif()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif ()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
target_compile_options(oecore PUBLIC
    -m64
    -fPIC
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden
    )
else()
target_compile_options(oecore PUBLIC
    -fPIC
    -nostdinc
    -fno-stack-protector
    -fvisibility=hidden
    )
endif()

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

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
