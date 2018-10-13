/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <tcps_u.h>
#include <openenclave/bits/types.h>
#include "../External/openenclave/include/openenclave/host.h"

#include <sgx.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TODO: this is being put into edger8r/host.h */
oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/* TODO: this should be put into edger8r/host.h */
/**
 * Create an enclave from an enclave image file.
 *
 * This function creates an enclave from an enclave image file. On successful
 * return, the enclave is fully initialized and ready to use.
 *
 * @param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the **oecore** library and signed by the
 * **oesign** tool.
 *
 * @param type The type of enclave supported by the enclave image file.
 *     - OE_ENCLAVE_TYPE_SGX - An SGX enclave
 *
 * @param flags These flags control how the enclave is run.
 *     It is the bitwise OR of zero or more of the following flags
 *     - OE_ENCLAVE_FLAG_DEBUG - runs the enclave in debug mode
 *     - OE_ENCLAVE_FLAG_SIMULATE - runs the enclave in simulation mode
 *
 * @param config Additional enclave creation configuration data for the specific
 * enclave type. This parameter is reserved and must be NULL.
 *
 * @param config_size The size of the **config** data buffer in bytes.
 *
 * @param enclave This points to the enclave instance upon success.
 *
 * @returns Returns OE_OK on success.
 *
 */
oe_result_t oe_create_enclave_v2(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    void (**ocall_table)(void*), /* TODO: type of this argument is still being discussed */
    uint32_t ocall_table_size,
    oe_enclave_t** enclave);

#define oe_acquire_enclave_mutex(enclave) TcpsAcquireTAMutex((sgx_enclave_id_t)enclave)
#define oe_release_enclave_mutex(enclave) TcpsReleaseTAMutex((sgx_enclave_id_t)enclave)

#ifdef __cplusplus
}
#endif
