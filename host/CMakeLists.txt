add_library(oehost STATIC
    aesm.c
    calls.c
    create.c
    elf.c
    enclave.c
    error.c
    exception.c
    files.c
    hexdump.c
    load.c
    ocalls.c
    quote.c
    registers.c
    result.c
    sgxdriver.c
    sgxmeasure.c
    sgxtypes.c
    sha.c
    spinlock.c
    tests.c
    thread.c
    typeinfo.c
    aep.S
    enter.S
    entersim.S
    )

# we and dependents need the OE includes to compile
target_link_libraries(oehost oe_includes)

find_library(CRYPTO_LIB NAMES crypto)
find_library(DL_LIB NAMES dl)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the host
target_link_libraries(oehost ${CRYPTO_LIB} ${DL_LIB} Threads::Threads)

target_compile_options(oehost PRIVATE 
    -Wall -Werror -Wno-attributes -Wmissing-prototypes
    -m64
    )
target_compile_definitions(oehost PRIVATE -DOE_BUILD_UNTRUSTED)

# convenience library for creating a host-app (that needs the -rdynamic link flag)
add_library(oehostapp INTERFACE)
target_link_libraries(oehostapp INTERFACE oehost -rdynamic)

# assemble lib-archive into proper dir
set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# install lib-archive upon install-time
install (TARGETS oehost ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
