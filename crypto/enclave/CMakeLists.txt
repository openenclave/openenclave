add_library(
    oecrypto 
    STATIC 
    sha.c
    cert.c
    random.c
    keys.c)

target_link_libraries(
    oecrypto 
    PUBLIC 
    mbedx509
    mbedtls
    mbedcrypto
    oelibc
    oe_includes)

target_compile_options(
    oecrypto 
    PUBLIC
    -m64 -fPIC
    -nostdinc
    $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
    -fno-stack-protector -fvisibility=hidden)

target_link_libraries(
    oecrypto 
    INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,-eOE_Main)

target_compile_definitions(oecrypto PRIVATE -DOE_BUILD_ENCLAVE)

set_property(
    TARGET 
    oecrypto 
    PROPERTY 
    ARCHIVE_OUTPUT_DIRECTORY 
    ${OE_LIBDIR}/openenclave/enclave)

install(
    TARGETS 
    oecrypto 
    ARCHIVE 
    DESTINATION 
    ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
