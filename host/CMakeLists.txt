if (UNIX)
set(PLATFORM_SRC
    thread-linux.c
    aesm-linux.c
    aep.S
    enter.S
    entersim.S
    )
elseif (WIN32)
set(PLATFORM_SRC
    thread-win.c
    aesm-win.c
    aep.asm
    enter.asm
    entersim.asm
    )
endif()

add_library(oehost STATIC
    registers.c
    strings.c
    fopen.c
    dupenv.c
    files.c
    calls.c
    create.c
    elf.c
    enclave.c
    error.c
    files.c
    hexdump.c
    load.c
    ocalls.c
    quote.c
    result.c
    sgxdriver.c
    sgxmeasure.c
    sgxtypes.c
    sha.c
    tests.c
    typeinfo.c
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
target_link_libraries(oehost ${CRYPTO_LIB} ${DL_LIB} Threads::Threads)

if(UNIX)
target_compile_options(oehost PRIVATE -Wno-attributes -Wmissing-prototypes -m64)
target_compile_definitions(oehost PRIVATE _GNU_SOURCE)
endif(UNIX)
target_compile_definitions(oehost PRIVATE OE_BUILD_UNTRUSTED)

# convenience library for creating a host-app (that needs the -rdynamic link flag)
add_library(oehostapp INTERFACE)
target_link_libraries(oehostapp INTERFACE oehost -rdynamic)

# assemble lib-archive into proper dir
set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# install lib-archive upon install-time
install (TARGETS oehost ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
