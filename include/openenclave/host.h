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

#define OE_MAX_ECALLS 1024
#define OE_MAX_OCALLS 1024

typedef void (*OE_OCallFunction)(uint64_t argIn, uint64_t* argOut);

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
OE_Result OE_TerminateEnclave(
    OE_Enclave* enclave);

/**
 * Perform a low-level enclave function call (ECALL).
 *
 * This function performs a low-level enclave function call by invoking the 
 * function indicated by the **func** parameter. The enclave defines and 
 * registers a corresponding function with the following signature.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut); 
 *
 * The meaning of the **argIn** arg **argOut** parameters is defined by the
 * implementer of the function and either may be null.
 *
 * OpenEnclave uses the low-level ECALL interface to implement internal calls, 
 * used by OE_CallEnclave() and OE_TerminateEnclave(). Enclave application 
 * developers are encouraged to use OE_CallEnclave() instead.
 *
 * At the software layer, this function sends an **ECALL** message to the 
 * enclave and waits for an **ERET** message. Note that the ECALL implementation
 * may call back into the host (an OCALL) before returning.
 *
 * At the hardware layer, this function executes the **ENCLU.EENTER**
 * instruction to enter the enclave. When the enclave returns from the ECALL, 
 * it executes the **ENCLU.EEXIT** instruction exit the enclave and to resume
 * host execution.
 *
 * Note that the return value only indicates whether the ECALL was called and
 * not whether it was successful. The ECALL implementation must define its own
 * error reporting scheme based on its parameters.
 *
 * @param func The number of the function to be called.
 * @param argsIn The input argument passed to the function.
 * @param argsIn The output argument passed back from the function.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_FAILED The function failed.
 * @retval OE_INVALID_PARAMETER One or more parameters is invalid.
 * @retval OE_OUT_OF_THREADS No enclave threads are available to make the call.
 * @retval OE_UNEXPECTED An unexpected error occurred.
 *
 */
OE_Result OE_ECall(
    OE_Enclave* enclave,
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut);

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
 * This function is implemented using the low-level **OE_OCall()** interface
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
OE_Result OE_CallEnclave(
    OE_Enclave* enclave,
    const char* func,
    void* args);

/**
 * Registers a low-level OCALL function.
 *
 * This function registers a low-level OCALL function that may be called
 * from the encalve by the **OE_OCall()** function. The registered function
 * has the following prototype.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * This interface is intended mainly for internal use and developers are
 * encouraged to use the high-level interface instead.
 *
 * @param func The number of the function to be called.
 * @param ocall The address of the function to be called.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_OUT_OF_RANGE The function number was greater than OE_MAX_OCALLS.
 * @retval OE_ALREADY_IN_USE The function number is already in use.
 *
 */
OE_Result OE_RegisterOCall(
    uint32_t func,
    OE_OCallFunction ocall);

OE_Result OE_GetQuote(
    const void* report,
    size_t reportSize,
    void* quote,
    size_t* quoteSize);

OE_EXTERNC_END

#endif /* _OE_HOST_H */
