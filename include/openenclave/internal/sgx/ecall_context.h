// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#ifndef _OE_INTERNAL_ECALL_CONTEXT_H
#define _OE_INTERNAL_ECALL_CONTEXT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/calls.h>

OE_EXTERNC_BEGIN

typedef struct _oe_ecall_context
{
    // Storage for making ocall
    oe_call_host_function_args_t ocall_args;
    uint64_t ocall_buffer_size;
    uint8_t* ocall_buffer;

    // Exit frame information for ocall stack stitching.
    uint64_t debug_eexit_rip;
    uint64_t debug_eexit_rbp;
    uint64_t debug_eexit_rsp;
} oe_ecall_context_t;

/**
 * Fetch the ocall_args field if an ecall context has been passed in.
 */
oe_call_host_function_args_t* oe_ecall_context_get_ocall_args();

/**
 * Get the ecall context's buffer if it is of an equal or larger size than the
 * given size.
 */
void* oe_ecall_context_get_ocall_buffer(uint64_t size);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_ECALL_CONTEXT_H */
