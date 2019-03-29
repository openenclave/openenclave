# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LINUX_SGX_DIR ${PROJECT_SOURCE_DIR}/3rdparty/linux-sgx)

add_library(oeresolver_hostresolver_enc STATIC
    host_resolver.c)

target_include_directories(oeresolver_hostresolver_enc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(oeresolver_hostresolver_enc PUBLIC oeenclave mbedcrypto oelibc)

set_property(TARGET oeresolver_hostresolver_enc PROPERTY
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeresolver_hostresolver_enc
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
