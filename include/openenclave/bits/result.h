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
#include "types.h"

OE_EXTERNC_BEGIN

/**
 * Result codes.
 */
typedef enum _oe_result {
    OE_OK,
    OE_FAILURE,
    OE_BUFFER_TOO_SMALL,
    OE_INVALID_PARAMETER,
    OE_REENTRANT_ECALL,
    OE_OUT_OF_MEMORY,
    OE_OUT_OF_THREADS,
    OE_UNEXPECTED,
    OE_VERIFY_FAILED,
    OE_NOT_FOUND,
    OE_INTEGER_OVERFLOW,
    OE_WRONG_TYPE,
    OE_OUT_OF_BOUNDS,
    OE_OVERLAPPED_COPY,
    OE_FAILED_OPT_CONSTRAINT,
    OE_IOCTL_FAILED,
    OE_UNSUPPORTED,
    OE_READ_FAILED,
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
    OE_INVALID_SGX_CERT_EXTENSIONS,
    OE_MEMORY_LEAK,
    OE_BAD_ALIGNMENT,
    OE_TCB_INFO_PARSE_ERROR,
    OE_TCB_LEVEL_INVALID,
    OE_QUOTE_PROVIDER_LOAD_ERROR,
    OE_QUOTE_PROVIDER_CALL_ERROR,
    OE_INVALID_REVOCATION_INFO,
    OE_INVALID_UTC_DATE_TIME,
    __OE_RESULT_MAX = OE_ENUM_MAX,
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
