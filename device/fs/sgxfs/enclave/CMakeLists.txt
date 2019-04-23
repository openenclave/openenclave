# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(LINUX_SGX_DIR ${PROJECT_SOURCE_DIR}/3rdparty/linux-sgx)

add_library(oesgxfsenclave STATIC 
    crypto.c
    file_crypto.cpp
    file_flush.cpp
    file_init.cpp
    file_other.cpp
    file_read_write.cpp
    file_version.cpp
    getkey.c
    isoutside.c
    lru_cache.cpp
    memequal.c
    memset_s.c
    rand.c
    sgxfs.c
    sgx_tprotected_fs.cpp
    thread.c)

target_include_directories(oesgxfsenclave PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LINUX_SGX_DIR}
    ${LINUX_SGX_DIR}/linux-sgx/common/inc
    ${LINUX_SGX_DIR}/linux-sgx/common/inc/internal
    ${LINUX_SGX_DIR}/linux-sgx/sdk/protected_fs/sgx_tprotected_fs)

target_link_libraries(oesgxfsenclave 
    PUBLIC oelibcxx oeenclave mbedcrypto oelibc)

set_property(TARGET oesgxfsenclave PROPERTY 
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oesgxfsenclave 
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
