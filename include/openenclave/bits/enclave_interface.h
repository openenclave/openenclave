// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_ENCLAVE_INTERFACE_H
#define _OE_BITS_ENCLAVE_INTERFACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_interface
{
    uint64_t data[6];
} oe_interface_t;

typedef oe_result_t (*oe_interface_ecall_handler_t)(
    uint64_t function_id,
    const uint8_t* input_buffer,
    uint64_t input_buffer_size,
    uint8_t* output_buffer,
    uint64_t output_buffer_size);

oe_result_t oe_register_interface(
    oe_interface_t* interface,
    const char* identifier,
    oe_interface_ecall_handler_t handler);

OE_EXTERNC_END

#endif // _OE_BITS_ENCLAVE_INTERFACE_H
