// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file result.h
 *
 * This file defines Open Enclave return codes (results).
 *
 */
#ifndef _OE_BITS_RESULT_H
#define _OE_BITS_RESULT_H

#include "defs.h"

OE_EXTERNC_BEGIN

/**
 * Result codes.
 */
typedef enum _oe_result {
    OE_OK,
    OE_FAILURE,
    OE_BUFFER_TOO_SMALL,
    OE_INVALID_PARAMETER,
    OE_OUT_OF_MEMORY,
    OE_OUT_OF_STACK,
    OE_OUT_OF_THREADS,
    OE_ECALL_FAILED,
    OE_OCALL_FAILED,
    OE_UNEXPECTED,
    OE_VERIFY_FAILED,
    OE_NOT_FOUND,
    OE_INTEGER_OVERFLOW,
    OE_WRONG_TYPE,
    OE_UNIMPLEMENTED,
    OE_OUT_OF_BOUNDS,
    OE_OVERLAPPED_COPY,
    OE_UNKNOWN_FUNCTION,
    OE_FAILED_OPT_CONSTRAINT,
    OE_DYNAMIC_LOAD_FAILED,
    OE_DYNAMIC_SYMBOL_LOOKUP_FAILED,
    OE_BUFFER_OVERRUN,
    OE_BAD_MAGIC,
    OE_IOCTL_FAILED,
    OE_UNSUPPORTED,
    OE_UNKNOWN_OPTION,
    OE_READ_FAILED,
    OE_OUT_OF_RANGE,
    OE_ALREADY_IN_USE,
    OE_SERVICE_UNAVAILABLE,
    OE_ENCLAVE_ABORTING,
    OE_ENCLAVE_ABORTED,
    OE_PLATFORM_ERROR,
    OE_INVALID_CPUSVN,
    OE_INVALID_ISVSVN,
    OE_INVALID_KEYNAME,
    OE_DEBUG_DOWNGRADE,
    OE_QUOTE_PARSE_ERROR,
    OE_UNSUPPORTED_QE_CERTIFICATION,
    OE_BUSY,
    OE_NOT_OWNER,
    OE_MEMORY_LEAK,
    OE_BAD_ALIGNMENT,
} oe_result_t;

/**
 * Retrieve a string for a result code.
 *
 * This function retrieves a string description for the given **result**
 * parameter.
 *
 * @param result Retrieve string description for this result code.
 *
 * @returns Returns a pointer to a static string description.
 *
 */
const char* oe_result_str(oe_result_t result);

OE_EXTERNC_END

#endif /* _OE_BITS_RESULT_H */
