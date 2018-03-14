add_library(
    oecryptohost 
    STATIC
    init.c
    sha.c
    cert.c
    random.c
    rsa.c
    ec.c)

target_link_libraries(oecryptohost oe_includes)

if(UNIX)
    find_library(CRYPTO_LIB NAMES crypto)
    find_library(DL_LIB NAMES dl)
endif()

find_package(Threads REQUIRED)

if(UNIX)
    target_link_libraries(oecryptohost ${CRYPTO_LIB} ${DL_LIB} Threads::Threads)
elseif(WIN32)
    target_link_libraries(oecryptohost bcrypt)
endif()

if(UNIX)
    target_compile_options(
        oecryptohost 
        PRIVATE 
        -Wno-attributes 
        -Wmissing-prototypes 
        -m64)
    target_compile_definitions(oecryptohost PRIVATE _GNU_SOURCE)
endif(UNIX)

target_compile_definitions(oecryptohost PRIVATE OE_BUILD_UNTRUSTED)

set_property(
    TARGET 
    oecryptohost 
    PROPERTY 
    ARCHIVE_OUTPUT_DIRECTORY 
    ${OE_LIBDIR}/openenclave/host)

install(
    TARGETS 
    oecryptohost 
    ARCHIVE 
    DESTINATION 
    ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

