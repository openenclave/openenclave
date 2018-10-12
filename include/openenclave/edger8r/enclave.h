// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file enclave.h
 *
 * This file defines the internal functions and data-structures used by
 * oeedger8r generated code on the enclave side.
 * These internals are subject to change without notice.
 *
 */
#ifndef _OE_EDGER8R_ENCLAVE_H
#define _OE_EDGER8R_ENCLAVE_H

#ifdef _OE_EDGER8R_HOST_H
#error \
    "edger8r/enclave.h and edger8r/host.h must not be included in the same compilation unit."
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * The type of a function in ecall function table
 */
typedef void (*oe_ecall_func_t)(void*);

/**
 * Perform a high-level host function call (OCALL).
 *
 * Call the host function whose matching the given function_id.
 * The host function is expected to have the following signature:
 *
 *     void (*)(void* args);
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must
 * define its own error reporting scheme via the arguments or return value.
 *
 * @param function_id The id of the host function that will be called.
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
 */
oe_result_t oe_call_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * For hand-written enclaves, that use the older calling mechanism, define empty
 * ecall tables.
 */
#define OE_DEFINE_EMPTY_ECALL_TABLE()                            \
    OE_EXPORT_CONST oe_ecall_func_t _oe_ecalls_table[] = {NULL}; \
    OE_EXPORT_CONST size_t _oe_ecalls_table_size = 0

/**
 * Check that the given buffer lies in host memory.
 * Raise OE_INVALID_PARAMETER if check fails.
 * Allocate corresponding enclave-buffer and copy data.
 * Raise OE_OUT_OF_MEMORY if allocation fails.
 */
#define OE_CHECKED_COPY_INPUT(enc_ptr, host_ptr, size)          \
    do                                                          \
    {                                                           \
        if (host_ptr && !oe_is_outside_enclave(host_ptr, size)) \
        {                                                       \
            __result = OE_INVALID_PARAMETER;                    \
            goto done;                                          \
        }                                                       \
        enc_ptr = NULL;                                         \
        if (host_ptr)                                           \
        {                                                       \
            *(void**)&enc_ptr = malloc(size);                   \
            if (!enc_ptr)                                       \
            {                                                   \
                __result = OE_OUT_OF_MEMORY;                    \
                goto done;                                      \
            }                                                   \
            memcpy(enc_ptr, host_ptr, size);                    \
        }                                                       \
    } while (0)

/**
 * Check that the given buffer lies in host memory.
 * Raise OE_INVALID_PARAMETER if check fails.
 * Allocate corresponding enclave-buffer.
 * Raise OE_OUT_OF_MEMORY if allocation fails.
 */
#define OE_CHECKED_ALLOCATE_OUTPUT(enc_ptr, host_ptr, size)     \
    do                                                          \
    {                                                           \
        if (host_ptr && !oe_is_outside_enclave(host_ptr, size)) \
        {                                                       \
            __result = OE_INVALID_PARAMETER;                    \
            goto done;                                          \
        }                                                       \
        enc_ptr = NULL;                                         \
        if (host_ptr)                                           \
        {                                                       \
            *(void**)&enc_ptr = malloc(size);                   \
            if (!enc_ptr)                                       \
            {                                                   \
                __result = OE_OUT_OF_MEMORY;                    \
                goto done;                                      \
            }                                                   \
        }                                                       \
    } while (0)

/**
 * Copy enclave buffer to host buffer.
 */
#define OE_COPY_TO_HOST(host_ptr, enc_ptr, size) \
    do                                           \
    {                                            \
        if (!enc_ptr)                            \
            break;                               \
        *(void**)&host_ptr = (void*)__host_ptr;  \
        __host_ptr += (size_t)size;              \
        memcpy(host_ptr, enc_ptr, size);         \
    } while (0)

/**
 * Copy buffer from host to enclave.
 */
#define OE_COPY_FROM_HOST(enc_ptr, host_ptr, size)              \
    do                                                          \
    {                                                           \
        if (host_ptr && !oe_is_outside_enclave(host_ptr, size)) \
        {                                                       \
            __result = OE_INVALID_PARAMETER;                    \
            goto done;                                          \
        }                                                       \
        if (host_ptr)                                           \
            memcpy(enc_ptr, host_ptr, size);                    \
    } while (0)

#if __x86_64__ || _M_X64

// x86_64 processor.
#if defined(__clang__) || defined(__ICC) || defined(__INTEL_COMPILER) || \
    defined(__GNUC__) || defined(__GNUG__)

#define oe_lfence() __builtin_ia32_lfence()

#elif defined(_MSC_VER)

#include <intrin.h>
#define oe_lfence() _mm_lfence()

#else

// Not a recognized compiler.
#define oe_lfence() (void)0

#endif

#else

#define oe_lfence() (void)0

#endif

OE_EXTERNC_END

#endif // _OE_EDGER8R_ENCLAVE_H
