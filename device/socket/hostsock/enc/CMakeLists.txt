# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LINUX_SGX_DIR ${PROJECT_SOURCE_DIR}/3rdparty/linux-sgx)

add_library(oesocket_hostsocket_enc STATIC sockhost.c)

target_include_directories(oesocket_hostsocket_enc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(oesocket_hostsocket_enc PUBLIC oeenclave mbedcrypto oelibc)

set_property(TARGET oesocket_hostsocket_enc PROPERTY
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oesocket_hostsocket_enc
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
