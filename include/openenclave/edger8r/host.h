// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file host.h
 *
 * This file defines the internal functions and data-structures used by
 * oeedger8r generated code on the host side.
 * These internals are subject to change without notice.
 *
 */
#ifndef _OE_EDGER8R_HOST_H
#define _OE_EDGER8R_HOST_H

#ifdef _OE_EDGER8R_ENCLAVE_H
#error \
    "edger8r/enclave.h and edger8r/host.h must not be included in the same compilation unit."
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/edger8r/common.h>
#include <openenclave/edger8r/switchless.h>
#include <openenclave/host.h> // for oe_ocall_func_t

OE_EXTERNC_BEGIN

/**
 * Perform a high-level enclave function call (ECALL).
 *
 * Call the enclave function that matches the given function-id.
 * The enclave function is expected to have the following signature:
 *
 *     void (const uint8_t* input_buffer,
 *           size_t input_buffer_size,
 *           uint8_t* output_buffer,
 *           size_t output_buffer_size,
 *           size_t* output_bytes_written);
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme via the arguments or return value.
 *
 * @param function_id The id of the enclave function that will be called.
 * @param input_buffer Buffer containing inputs data.
 * @param input_buffer_size Size of the input data buffer.
 * @param output_buffer Buffer where the outputs of the host function are
 * written to.
 * @param output_buffer_size Size of the output buffer.
 * @param output_bytes_written Number of bytes written in the output buffer.
 *
 * @return OE_OK the call was successful.
 * @return OE_NOT_FOUND if the function_id does not correspond to a function.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_FAILURE the call failed.
 * @return OE_BUFFER_TOO_SMALL the input or output buffer was smaller than
 * expected.
 *
 */
oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * Perform a high-level enclave function call via the switchless calling
 * mechanism (ECALL).
 *
 * Call the enclave function that matches the given function-id.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme via the arguments or return value.
 *
 * @param enclave The enclave that will handle this function.
 * @param node The completed declaration for the function call.
 *
 * @return OE_OK the call was successful.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 *
 */
oe_result_t oe_call_synchronous_switchless_enclave_function(
    oe_enclave_t* enclave,
    oe_switchless_synchronous_ecall_t* node);

OE_EXTERNC_END

#endif // _OE_EDGER8R_HOST_H
