// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#ifndef _OE_HOST_SGX_ENCLAVE_COMMON_WRAPPER_H
#define _OE_HOST_SGX_ENCLAVE_COMMON_WRAPPER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#ifndef ENCLAVE_TYPE_SGX
#define ENCLAVE_TYPE_SGX                                                   \
    0x00000001 /* An enclave for the Intel Software Guard Extensions (SGX) \
                  architecture version 1. */
#endif
#ifndef ENCLAVE_TYPE_SGX2
#define ENCLAVE_TYPE_SGX2                                                  \
    0x00000002 /* An enclave for the Intel Software Guard Extensions (SGX) \
                  architecture version 2. */
#endif
#define ENCLAVE_TYPE_SGX1 ENCLAVE_TYPE_SGX

typedef enum
{
    ENCLAVE_PAGE_READ =
        1 << 0, /* Enables read access to the committed region of pages. */
    ENCLAVE_PAGE_WRITE =
        1 << 1, /* Enables write access to the committed region of pages. */
    ENCLAVE_PAGE_EXECUTE =
        1 << 2, /* Enables execute access to the committed region of pages. */
    ENCLAVE_PAGE_THREAD_CONTROL =
        1 << 8, /* The page contains a thread control structure. */
    ENCLAVE_PAGE_UNVALIDATED =
        1 << 12, /* The page contents that you supply are excluded from
                    measurement and content validation. */
} enclave_page_properties_t;

void* oe_sgx_enclave_create(
    void* base_address,
    size_t virtual_size,
    size_t initial_commit,
    uint32_t type,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error);

size_t oe_sgx_enclave_load_data(
    void* target_address,
    size_t target_size,
    const void* source_buffer,
    uint32_t data_properties,
    uint32_t* enclave_error);

bool oe_sgx_enclave_initialize(
    void* base_address,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error);

bool oe_sgx_enclave_delete(void* base_address, uint32_t* enclave_error);

bool oe_sgx_enclave_set_information(
    void* base_address,
    uint32_t info_type,
    void* input_info,
    size_t input_info_size,
    uint32_t* enclave_error);

#endif //  _OE_HOST_SGX_ENCLAVE_COMMON_WRAPPER_H
