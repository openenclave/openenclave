# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX)
set(PLATFORM_SRC
    crypto/cert.c
    crypto/ec.c
    crypto/init.c
    crypto/random.c
    crypto/rsa.c
    linux/aep.S
    linux/aesm.c
    linux/cpuid_count.c
    linux/enter.S
    linux/entersim.S
    linux/exception.c
    linux/hostthread.c
    linux/sgxioctl.c
    linux/sgxsign.c
    )
elseif (WIN32)
set(PLATFORM_SRC
    windows/aep.asm
    windows/aesm.c
    windows/enter.asm
    windows/entersim.asm
    windows/exception.c
    windows/hostthread.c
    windows/sgxsign.c
    )
endif()

add_library(oehost STATIC
    calls.c
    create.c
    dupenv.c
    elf.c
    enclave.c
    enclavemanager.c
    error.c
    files.c
    fopen.c
    hexdump.c
    load.c
    memalign.c
    ocalls.c
    quote.c
    registers.c
    report.c
    result.c
    sgxload.c
    sgxmeasure.c
    sgxtypes.c
    signkey.c
    strings.c
    tests.c
    typeinfo.c
    crypto/sha.c
    ${PLATFORM_SRC}
    )

# we and dependents need the OE includes to compile
target_link_libraries(oehost oe_includes)

if(UNIX)
find_library(CRYPTO_LIB NAMES crypto)
find_library(DL_LIB NAMES dl)
endif(UNIX)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the host
if(UNIX)
target_link_libraries(oehost ${CRYPTO_LIB} ${DL_LIB} Threads::Threads)
elseif(WIN32)
target_link_libraries(oehost bcrypt)
endif()

if(UNIX)
target_compile_options(oehost PRIVATE -Wno-attributes -Wmissing-prototypes -fPIC -m64)
target_compile_definitions(oehost PRIVATE _GNU_SOURCE)
endif(UNIX)
target_compile_definitions(oehost PRIVATE OE_BUILD_UNTRUSTED)

# convenience library for creating a host-app (that needs the -rdynamic link flag)
add_library(oehostapp INTERFACE)
if(UNIX)
target_link_libraries(oehostapp INTERFACE oehost -rdynamic)
elseif(WIN32)
target_link_libraries(oehostapp INTERFACE oehost)
endif()

# assemble lib-archive into proper dir
set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# install lib-archive upon install-time
install(TARGETS oehost EXPORT openenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

# provide oehostapp to install-base as well
install(TARGETS oehostapp EXPORT openenclave)

