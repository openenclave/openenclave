/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <tcps_u.h>
#include <openenclave/bits/types.h>
#include "../../include/openenclave/host.h"

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

#define oe_acquire_enclave_mutex(enclave) TcpsAcquireTAMutex((sgx_enclave_id_t)enclave)
#define oe_release_enclave_mutex(enclave) TcpsReleaseTAMutex((sgx_enclave_id_t)enclave)

#ifdef __cplusplus
}
#endif
