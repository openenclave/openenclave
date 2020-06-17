// Copyright (c) Open Enclave SDK contributors.
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
#include <openenclave/edger8r/common.h>

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/wchar.h>

OE_EXTERNC_BEGIN

/**
 * The type of a function in ecall function table
 */
typedef void (*oe_ecall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * Perform a high-level host function call (OCALL).
 *
 * Call the host function whose matching the given function_id.
 * The host function is expected to have the following signature:
 *
 *     void (const uint8_t* input_buffer,
 *           size_t input_buffer_size,
 *           uint8_t* output_buffer,
 *           size_t output_buffer_size,
 *           size_t* output_bytes_written);
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
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * Perform a high-level host function call (OCALL) switchlessly.
 *
 * Call the host function whose matching the given function_id.
 * The host function is expected to have the following signature:
 *
 *     void (const uint8_t* input_buffer,
 *           size_t input_buffer_size,
 *           uint8_t* output_buffer,
 *           size_t output_buffer_size,
 *           size_t* output_bytes_written);
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
oe_result_t oe_switchless_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

/**
 * Allocate a buffer of given size for doing an ocall.
 *
 * The buffer may or may not be allocated in host memory.
 * The buffer should be treated as untrusted.
 *
 * @param size The size in bytes of the buffer.
 * @returns pointer to the allocated buffer.
 * @return NULL if allocation failed.
 */
void* oe_allocate_ocall_buffer(size_t size);

/**
 * Free the buffer allocated for ocalls.
 *
 * @param buffer The buffer allocated via oe_allocate_ocall_buffer.
 */
void oe_free_ocall_buffer(void* buffer);

/**
 * Allocate a buffer of given size for doing a switchless ocall.
 *
 * The buffer may or may not be allocated in host memory.
 * The buffer should be treated as untrusted.
 *
 * @param size The size in bytes of the buffer.
 * @returns pointer to the allocated buffer.
 * @return NULL if allocation failed.
 */
void* oe_allocate_switchless_ocall_buffer(size_t size);

/**
 * Free the buffer allocated for switchless ocalls.
 *
 * @param buffer The buffer allocated via oe_allocate_ocall_buffer.
 */
void oe_free_switchless_ocall_buffer(void* buffer);

/**
 * For hand-written enclaves, that use the older calling mechanism, define empty
 * ecall tables.
 */
#define OE_DEFINE_EMPTY_ECALL_TABLE()                             \
    OE_EXPORT_CONST oe_ecall_func_t __oe_ecalls_table[] = {NULL}; \
    OE_EXPORT_CONST size_t __oe_ecalls_table_size = 0

#if __x86_64__ || _M_X64
/**
 * Get the internal status of the enclave.
 *
 * @returns read-only copy of the internal status.
 */
oe_result_t oe_get_enclave_status();
#else // Make oe_get_enclave_status a no-op for non x86-64 platforms.
OE_INLINE oe_result_t oe_get_enclave_status()
{
    return OE_OK;
}
#endif

// Define oe_lfence for Spectre mitigation in x86-64 platforms.
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
#error Not a supported compiler

#endif

#else

// On non x86-64 platforms, oe_lfence does nothing.
#define oe_lfence() (void)0

#endif

OE_EXTERNC_END

#endif // _OE_EDGER8R_ENCLAVE_H
