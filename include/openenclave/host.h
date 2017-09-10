#ifndef _OE_HOST_H
#define _OE_HOST_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "defs.h"
#include "types.h"
#include "result.h"
#include "thread.h"
#include "sha.h"
#include "typeinfo.h"
#include "atomic.h"

OE_EXTERNC_BEGIN

#define OE_BUILD_HOST

#ifdef __cplusplus
# define OE_OCALL OE_EXTERNC OE_EXPORT
#else
# define OE_OCALL OE_EXPORT
#endif

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
 * \param path The path of an enclave image file in ELF-64 format. This
 * file must have been linked with the \b oeenclave library and signed by the
 * \b oesign tool.
 *
 * \param flags These flags control how the enclave is run.
 *     - OE_FLAG_DEBUG - runs the enclave in debug mode
 *     - OE_FLAG_SIMULATION - runs the enclave in simulation mode
 *
 * \param enclave This points to the enclave instance upon succeess.
 *
 * \returns If successful, this function returns OE_OK.
 *
 */
OE_Result OE_CreateEnclave(
    const char* path,
    uint32_t flags,
    OE_Enclave** enclave);

/**
 * Terminates an enclave and reclaims its resources.
 *
 * This function terminates an enclave to reclaims all of its resources. This
 * involves unmapping the memory that was mapped by \b OE_CreateEnclave().
 * Once this is peformed, the enclave can no longer be accessed.
 *
 * \param enclave The instance of the enclave to be terminated.
 *
 * \returns If successful, this function return OE_OK
 *
 */
OE_Result OE_TerminateEnclave(
    OE_Enclave* enclave);

OE_Result OE_CallEnclave(
    OE_Enclave* enclave,
    const char* func,
    void* args);

OE_Result OE_GetQuote(
    const void* report,
    size_t reportSize,
    void* quote,
    size_t* quoteSize);

OE_Result __OE_ECall(
    OE_Enclave* enclave,
    int func,
    uint64_t argIn,
    uint64_t* argOut);

OE_PRINTF_FORMAT(3, 4)
void __OE_PutErr(
    const char* file,
    unsigned int line,
    const char* format, 
    ...);

void OE_SetProgramName(
    const char* name);

#define OE_PutErr(...) __OE_PutErr(__FILE__, __LINE__, __VA_ARGS__)

OE_EXTERNC_END

#endif /* _OE_HOST_H */
