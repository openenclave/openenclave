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

#define OE_ENCLAVE_FLAG_DEBUG 0x00000001
#define OE_ENCLAVE_FLAG_SIMULATE 0x00000002
#define OE_ENCLAVE_FLAG_RESERVED \
    (~(OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE))

/**
 * Creates an enclave from an enclave image file.
 *
 * This function creates an enclave from an enclave image file. On successful
 * return, the enclave is fully initialized and ready to use.
 *
 * @param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the **oeenclave** library and signed by the
 * **oesign** tool.
 *
 * @param type The type of enclave supported by the enclave image file.
 *     - OE_ENCLAVE_TYPE_SGX - An SGX enclave
 *
 * @param flags These flags control how the enclave is run.
 *     - OE_ENCLAVE_FLAG_DEBUG - runs the enclave in debug mode
 *     - OE_ENCLAVE_FLAG_SIMULATE - runs the enclave in simulation mode
 *
 * @param config Additional enclave creation configuration data for the specific
 * enclave type. This parameter is reserved and must be NULL.
 *
 * @param configSize The size of the **config** data buffer in bytes.
 *
 * @param enclave This points to the enclave instance upon success.
 *
 * @returns Returns OE_OK on success.
 *
 */
OE_Result OE_CreateEnclave(
    const char* path,
    OE_EnclaveType type,
    uint32_t flags,
    const void* config,
    uint32_t configSize,
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

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param reportSize The size of the **report** buffer.
 * @param parsedReport The **OE_Report** structure to populate with the report
 * properties in a standard format. The *parsedReport* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 */
OE_Result OE_ParseReport(
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport);

/**
 * Verify the integrity of the report and its signature.
 *
 * This function verifies that the report signature is valid. If the report is
 * local, it verifies that it is correctly signed by the enclave
 * platform. If the report is remote, it verifies that the signing authority is
 * rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param report The buffer containing the report to verify.
 * @param reportSize The size of the **report** buffer.
 * @param parsedReport Optional **OE_Report** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
OE_Result OE_VerifyReport(
    OE_Enclave* enclave,
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport);

OE_EXTERNC_END

#endif /* _OE_HOST_H */
