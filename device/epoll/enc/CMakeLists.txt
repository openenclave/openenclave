# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LINUX_SGX_DIR ${PROJECT_SOURCE_DIR}/3rdparty/linux-sgx)

add_library(oe_epoll_enc STATIC
    hostepoll.c)

target_include_directories(oe_epoll_enc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(oe_epoll_enc PUBLIC oeenclave mbedcrypto oelibc)

set_property(TARGET oe_epoll_enc PROPERTY
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oe_epoll_enc
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
