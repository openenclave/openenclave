// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * \file host.h
 *
 * This file defines the programming interface for developing host applications.
 *
 */
#ifndef _OE_HOST_H
#define _OE_HOST_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bits/sha.h"
#include "defs.h"
#include "report.h"
#include "result.h"
#include "types.h"

OE_EXTERNC_BEGIN

#define OE_OCALL OE_EXTERNC OE_EXPORT

typedef struct _OE_Enclave OE_Enclave;

#define OE_FLAG_DEBUG 1
#define OE_FLAG_SIMULATE 2

/**
 * Creates an enclave from an enclave image file.
 *
 * This function creates an enclave from an enclave image file. While creating
 * the enclave, this function interacts with the Intel(R) SGX drviver and the
 * Intel(R) AESM service. Enclave creation peforms the following steps.
 *     - Loads an enclave image file
 *     - Maps the enclave memory image onto the driver device (/dev/isgx)
 *     - Lays out the enclave memory image and injects metadata
 *     - Asks the driver to create the enclave (ECREATE)
 *     - Asks the driver to add the pages to the EPC (EADD/EEXTEND)
 *     - Asks the Intel(R) launch enclave (LE) for a launch token (EINITKEY)
 *     - Asks the driver to initialize the enclave with the token (EINIT)
 *
 * Once these steps have been performed, the enclave is ready to use.
 *
 * @param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the **oeenclave** library and signed by the
 * **oesign** tool.
 *
 * @param flags These flags control how the enclave is run.
 *     - OE_FLAG_DEBUG - runs the enclave in debug mode
 *     - OE_FLAG_SIMULATION - runs the enclave in simulation mode
 *
 * @param enclave This points to the enclave instance upon succeess.
 *
 * @returns Returns OE_OK on success.
 *
 */
OE_Result OE_CreateEnclave(
    const char* path,
    uint32_t flags,
    OE_Enclave** enclave);

/**
 * Terminates an enclave and reclaims its resources.
 *
 * This function terminates an enclave and reclaims its resources. This
 * involves unmapping the memory that was mapped by **OE_CreateEnclave()**.
 * Once this is peformed, the enclave can no longer be accessed.
 *
 * @param enclave The instance of the enclave to be terminated.
 *
 * @returns Returns OE_OK on success.
 *
 */
OE_Result OE_TerminateEnclave(OE_Enclave* enclave);

/**
 * Perform a high-level enclave function call (ECALL).
 *
 * Call the enclave function whose name is given by the **func** parameter.
 * The enclave must define a corresponding function with the following
 * prototype.
 *
 *     OE_ECALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * This function is implemented using the low-level OE_OCall() interface
 * where the function number is given by the **OE_FUNC_CALL_ENCLAVE** constant.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The ECALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * @param func The name of the enclave function that will be called.
 * @param args The arguments to be passed to the enclave function.
 *
 * @returns This function return **OE_OK** on success.
 *
 */
OE_Result OE_CallEnclave(OE_Enclave* enclave, const char* func, void* args);

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **reportData** parameter.
 *
 * If the *reportBuffer* is NULL or *reportSize* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @param enclave The handle to the enclave that will generate the report.
 * @param options Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_OPTIONS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param reportData The report data that will be included in the report.
 * @param reportDataSize The size of the **reportData** in bytes.
 * @param optParams Optional additional parameters needed for the current
 * enclave type. For SGX, this can be SGX_TargetInfo for local attestation.
 * @param optParamsSize The size of the **enclaveParams** buffer.
 * @param reportBuffer The buffer to where the resulting report will be copied.
 * @param reportBufferSize The size of the **report** buffer. This is set to the
 * required size of the report buffer on return.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **reportBuffer** buffer is NULL or too small.
 * @retval OE_OUT_OF_MEMORY Failed to allocate memory.
 *
 */
OE_Result OE_GetReport(
    OE_Enclave* enclave,
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize);

OE_EXTERNC_END

#endif /* _OE_HOST_H */
