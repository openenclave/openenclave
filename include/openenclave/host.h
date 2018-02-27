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
 * Gets a quote from the Intel(R) quote enclave.
 *
 * This function obtains a quote for the **report** parameter. Enclaves create
 * reports by executing the ENCLU.EREPORT instruction. One way an enclave may
 * create a report is by calling OE_GetReportForRemoteAttestation().
 *
 * This function obtains a quote from the AESM service, which forwards the
 * request to the Intel(R) quote enclave.
 *
 * If the *quoteSize* parameter is too small, this function resets it to
 * the required size and returns OE_BUFFER_TOO_SMALL.
 *
 * @param report The report for which the quote is desired.
 * @param reportSize The size of the **report** buffer.
 * @param quote The quote is written to this buffer.
 * @param quoteSize The size of the **quote** buffer.
 *
 * @retval OE_OK The quote was successfully obtained.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @retval OE_BUFFER_TOO_SMALL The **quote** buffer is too small.
 * @retval OE_SERVICE_UNAVAILABLE The AESM service is unavailable.
 *
 */
OE_Result OE_GetQuote(
    const void* report,
    size_t reportSize,
    void* quote,
    size_t* quoteSize);

OE_EXTERNC_END

#endif /* _OE_HOST_H */
