# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    ../common/quote.c
    assert.c
    atexit.c
    calls.c
    cert.c
    cmac.c
    cpuid.c
    ec.c
    enclavelibc/enclavelibc.c
    enclavelibc/gmtime.c
    enclavelibc/printf.c
    enclavelibc/rand.c
    enclavelibc/string.c
    enclavelibc/malloc.c
    entropy.c
    exception.c
    globals.c
    hexdump.c
    hostcalls.c
    hoststack.c
    init.c
    intstr.c
    jump.c
    key.c
    keys.c
    memory.c
    once.c
    random.c
    report.c
    result.c
    rsa.c
    sbrk.c
    sha.c
    spinlock.c
    strtoul.c
    td.c
    thread.c
    time.c
    verify.c
    exit.S
    getkey.S
    main.S)

target_link_libraries(oeenclave PUBLIC 
    oe_includes 
    mbedcrypto)

# we strip the default include containing the compiler-provided intrinsics
# add it back in
target_include_directories(oeenclave SYSTEM PRIVATE ${OE_C_COMPILER_INCDIR})

target_compile_options(oeenclave PUBLIC
    -m64 -fPIC
    -nostdinc
    $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
    -fno-stack-protector -fvisibility=hidden)

if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()

target_compile_definitions(oeenclave PUBLIC OE_BUILD_ENCLAVE)

target_link_libraries(oeenclave INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,-eoe_main)

# jump.s must be optimized for the correct call-frame.
set_source_files_properties(jump.c PROPERTIES COMPILE_FLAGS -O2)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave 
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
