/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include "../../../../3rdparty/SGXSDK/include/sgx_edger8r.h"  /* SGX API prototypes to map */

/* We currently assume the macros below are only used from generated code. */

/* In SGX, sgx_ecall does not take the buffer length.  In OP-TEE, we need
 * the buffer length so we assume that the generated code uses a structure
 * we can take sizeof().  That is, currently an ecall with 0 argumnents is
 * not supported because the generated code would have a NULL ptr and there
 * seems to be no way to define a macro that works when ptr could either be
 * null or a pointer, and the "ms" variable may or may not exist.
 */
#define sgx_ecall(eid, id, ptable, ptr) sgx_optee_ecall((eid), (id), (ptable), (ptr), sizeof(*(ptr)))

sgx_status_t sgx_optee_ocall(
    const unsigned int index,
    void* buffer,
    size_t bufferSize);

sgx_status_t
optee_ocall(
    const unsigned int index,
    const void* inputBuffer,
    size_t inputBufferSize,
    void* outputBuffer,
    size_t outputBufferSize);

sgx_status_t sgx_optee_ecall(const sgx_enclave_id_t eid,
                             const int index,
                             const void* ocall_table,
                             void* inOutBuffer,
                             size_t inOutBufferLength);
