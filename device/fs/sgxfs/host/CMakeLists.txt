# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LINUX_SGX_DIR ${PROJECT_SOURCE_DIR}/3rdparty/linux-sgx)

add_library(oesgxfshost STATIC
    handleocall.c
    sgx_unprotected.cpp)

target_include_directories(oesgxfshost PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${LINUX_SGX_DIR}
    ${LINUX_SGX_DIR}/linux-sgx/common/inc
    ${LINUX_SGX_DIR}/linux-sgx/sdk/protected_fs/sgx_uprotected_fs)

set_property(TARGET oesgxfshost 
    PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oesgxfshost EXPORT openenclave-targets 
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
