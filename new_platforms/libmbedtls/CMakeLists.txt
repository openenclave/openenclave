# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(SGX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I\"${SGXSDKInstallPath}/include\"")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I\"${SGXSDKInstallPath}/include/tlibc\"")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I\"${NP_PATH}/include/sgx/enclave\"")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I\"${NP_PATH}/include\"")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I\"${OE_PATH}/include\"")

    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -I\"${SGXSDKInstallPath}/include\"")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -I\"${SGXSDKInstallPath}/include/tlibc\"")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -I\"${NP_PATH}/include\"")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -I\"${OE_PATH}/include\"")

    if(WIN32)
        string(REPLACE "/RTC1" "" CMAKE_C_FLAGS       "${CMAKE_C_FLAGS}")
        string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

        string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_C_FLAGS       "${CMAKE_C_FLAGS}")
        string(REGEX REPLACE "(-D|/D)[^ ]* " "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

        set(CMAKE_C_FLAGS       "${CMAKE_C_FLAGS} /X /DOE_NO_SAL /D_TLIBC_WARN_DEPRECATED_FUNCTIONS_ /wd4996")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /X /DOE_NO_SAL /D_TLIBC_WARN_DEPRECATED_FUNCTIONS_ /wd4996")
    endif()
endif()

# Create a patched version of mbed TLS's `config.h` that the external
# project depends on.
set(MBEDTLS_CERTS_C $<CONFIG:Debug>)
set(MBEDTLS_DEBUG_C $<CONFIG:Debug>)
set(MBEDTLS_OE_INCLUDE_ENCLAVE_H TRUE)

configure_file(${OE_PATH}/3rdparty/mbedtls/config.h config.h) # This copies from source to binary folders.

set(PREFIX $<IF:$<CONFIG:RelWithDebInfo>,Release,$<CONFIG>>)

include(ExternalProject)
ExternalProject_Add(mbedtls-wrap
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${OE_PATH}/3rdparty/mbedtls/mbedtls <SOURCE_DIR>

    UPDATE_COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/config.h <SOURCE_DIR>/include/mbedtls/config.h

    CMAKE_ARGS
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG}
        -DUSE_STATIC_MBEDTLS_LIBRARY=1

    # This is a no-op to override the default.
    INSTALL_COMMAND "")

ExternalProject_Get_property(mbedtls-wrap SOURCE_DIR)
ExternalProject_Get_property(mbedtls-wrap BINARY_DIR)

add_library(mbedtls_enc STATIC IMPORTED GLOBAL)
add_library(mbedx509_enc STATIC IMPORTED GLOBAL)
add_library(mbedcrypto_enc STATIC IMPORTED GLOBAL)

add_dependencies(mbedtls_enc mbedtls-wrap)
add_dependencies(mbedx509_enc mbedtls-wrap)
add_dependencies(mbedcrypto_enc mbedtls-wrap)

if(MSVC)
    set_target_properties(mbedtls_enc PROPERTIES
        IMPORTED_LOCATION_DEBUG ${BINARY_DIR}/library/Debug/mbedtls.lib
        IMPORTED_LOCATION_RELEASE ${BINARY_DIR}/library/Release/mbedtls.lib
        IMPORTED_LOCATION_RELWITHDEBINFO ${BINARY_DIR}/library/RelWithDebInfo/mbedtls.lib)

    set_target_properties(mbedx509_enc PROPERTIES
        IMPORTED_LOCATION_DEBUG ${BINARY_DIR}/library/Debug/mbedx509.lib
        IMPORTED_LOCATION_RELEASE ${BINARY_DIR}/library/Release/mbedx509.lib
        IMPORTED_LOCATION_RELWITHDEBINFO ${BINARY_DIR}/library/RelWithDebInfo/mbedx509.lib)

    set_target_properties(mbedcrypto_enc PROPERTIES
        IMPORTED_LOCATION_DEBUG ${BINARY_DIR}/library/Debug/mbedcrypto.lib
        IMPORTED_LOCATION_RELEASE ${BINARY_DIR}/library/Release/mbedcrypto.lib
        IMPORTED_LOCATION_RELWITHDEBINFO ${BINARY_DIR}/library/RelWithDebInfo/mbedcrypto.lib)
else()
    set_target_properties(mbedtls_enc PROPERTIES
        IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedtls.a)

    set_target_properties(mbedx509_enc PROPERTIES
        IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedx509.a)

    set_target_properties(mbedcrypto_enc PROPERTIES
        IMPORTED_LOCATION ${BINARY_DIR}/library/libmbedcrypto.a)
endif()
