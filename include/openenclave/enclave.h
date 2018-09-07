// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file enclave.h
 *
 * This file defines the programming interface for developing enclaves.
 *
 */
#ifndef _OE_ENCLAVE_H
#define _OE_ENCLAVE_H

#ifdef _OE_HOST_H
#error "enclave.h and host.h must not be included in the same compilation unit."
#endif

#include "bits/defs.h"
#include "bits/exception.h"
#include "bits/properties.h"
#include "bits/report.h"
#include "bits/result.h"
#include "bits/types.h"

/**
 * @cond IGNORE
 */
OE_EXTERNC_BEGIN

/**
 * @endcond
 */

/**
 * Register a new vectored exception handler.
 *
 * Call this function to add a new vectored exception handler. If successful,
 * the registered handler will be called when an exception happens inside the
 * enclave.
 *
 * @param isFirstHandler The parameter indicates that the input handler should
 * be the first exception handler to be called. If it is false, the input
 * handler will be appended to the end of exception handler chain, otherwise
 * it will be added as the first handler in the exception handler chain.
 * @param vectoredHandler The input vectored exception handler to register. It
 * must be a function defined in the enclave. The same handler can only be
 * registered once; a 2nd registration will fail. If the function succeeds, the
 * handler may be removed later by passing it to
 * oe_remove_vectored_exception_handler().
 *
 * @returns OE_OK successful
 * @returns OE_INVALID_PARAMETER a parameter is invalid
 * @returns OE_FAILED failed to add handler
*/
oe_result_t oe_add_vectored_exception_handler(
    bool isFirstHandler,
    oe_vectored_exception_handler_t vectoredHandler);

/**
* Remove an existing vectored exception handler.
*
* @param vectoredHandler The pointer to a registered exception handler returned
* from a successful oe_add_vectored_exception_handler() call.
*
* @returns OE_OK success
* @returns OE_INVALID_PARAMETER a parameter is invalid
* @returns OE_FAILED failed to remove handler
*/
oe_result_t oe_remove_vectored_exception_handler(
    oe_vectored_exception_handler_t vectoredHandler);

/**
 * Perform a high-level enclave function call (OCALL).
 *
 * Call the host function whose name is given by the **func** parameter.
 * The host must define a corresponding function with the following
 * prototype.
 *
 *     OE_OCALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * While handling the OCALL, the host is not allowed to make an ECALL back into
 * the enclave. A re-entrant ECALL will fail and return OE_REENTRANT_ECALL.
 *
 * @param func The name of the enclave function that will be called.
 * @param args The arguments to be passed to the enclave function.
 *
 * @returns This function return **OE_OK** on success.
 *
 */
oe_result_t oe_call_host(const char* func, void* args);

/**
 * Perform a high-level host function call (OCALL).
 *
 * Call the host function whose address is given by the **func** parameter,
 * which is the address of a function defined in the host with the following
 * prototoype.
 *
 *     OE_OCALL void (*)(void* args);
 *
 * The meaning of the **args** parameter is defined by the implementer of the
 * function and may be null.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must
 * define its own error reporting scheme based on **args**.
 *
 * @param func The address of the host function that will be called.
 * @param args The arguments to be passed to the host function.
 *
 * @return OE_OK the call was successful.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_FAILURE the call failed.
 */
oe_result_t oe_call_host_by_address(
    void (*func)(void*, oe_enclave_t*),
    void* args);

/**
 * Check whether the given buffer is strictly within the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly within the enclave's memory. If so, return true. If any
 * portion of the buffer lies outside the enclave's memory, return false.
 *
 * @param ptr The pointer pointer to buffer.
 * @param size The size of buffer
 *
 * @retval true The buffer is strictly within the enclave.
 * @retval false At least some part of the buffer is outside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_within_enclave(const void* ptr, size_t size);

/**
 * Check whether the given buffer is strictly outside the enclave.
 *
 * Check whether the buffer given by the **ptr** and **size** parameters is
 * strictly outside the enclave's memory. If so, return true. If any
 * portion of the buffer lies within the enclave's memory, return false.
 *
 * @param ptr The pointer to buffer.
 * @param size The size of buffer.
 *
 * @retval true The buffer is strictly outside the enclave.
 * @retval false At least some part of the buffer is inside the enclave, or
 * the arguments are invalid. For example, if **ptr** is null or **size**
 * causes arithmetic operations to wrap.
 *
 */
bool oe_is_outside_enclave(const void* ptr, size_t size);

/**
 * Allocate bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and returns the
 * address of the allocated memory. The implementation performs an OCALL to
 * the host, which calls malloc(). To free the memory, it must be passed to
 * oe_host_free().
 *
 * @param size The number of bytes to be allocated.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_malloc(size_t size);

/**
 * Reallocate bytes from the host's heap.
 *
 * This function changes the size of the memory block pointed to by **ptr**
 * on the host's heap to **size** bytes. The memory block may be moved to a
 * new location, which is returned by this function. The implementation
 * performs an OCALL to the host, which calls realloc(). To free the memory,
 * it must be passed to oe_host_free().
 *
 * @param ptr The memory block to change the size of. If NULL, this method
 * allocates **size** bytes as if oe_host_malloc was invoked. If not NULL,
 * it should be a pointer returned by a previous call to oe_host_calloc,
 * oe_host_malloc or oe_host_realloc.
 * @param size The number of bytes to be allocated. If 0, this method
 * deallocates the memory at **ptr**. If the new size is larger, the value
 * of the memory in the new allocated range is indeterminate.
 *
 * @returns The pointer to the reallocated memory or NULL if **ptr** was
 * freed by setting **size** to 0. This method also returns NULL if it was
 * unable to reallocate the memory, in which case the original **ptr**
 * remains valid and its contents are unchanged.
 *
 */
void* oe_host_realloc(void* ptr, size_t size);

/**
 * Allocate zero-filled bytes from the host's heap.
 *
 * This function allocates **size** bytes from the host's heap and fills it
 * with zero character. It returns the address of the allocated memory. The
 * implementation performs an OCALL to the host, which calls calloc().
 * To free the memory, it must be passed to oe_host_free().
 *
 * @param nmemb The number of elements to be allocated and zero-filled.
 * @param size The size of each element.
 *
 * @returns The allocated memory or NULL if unable to allocate the memory.
 *
 */
void* oe_host_calloc(size_t nmemb, size_t size);

/**
 * Release allocated memory.
 *
 * This function releases memory allocated with oe_host_malloc() or
 * oe_host_calloc() by performing an OCALL where the host calls free().
 *
 * @param ptr Pointer to memory to be released or null.
 *
 */
void oe_host_free(void* ptr);

/**
 * Make a heap copy of a string.
 *
 * This function allocates memory on the host's heap, copies no more than
 * *n* bytes from the **str** parameter to that memory, and returns a pointer
 * to the newly allocated memory.
 *
 * @param str The string to be copied.
 * @param n The number of characters to be copied.
 *
 * @returns A pointer to the newly allocated string or NULL if unable to
 * allocate the storage.
 */
char* oe_host_strndup(const char* str, size_t n);

/**
 * Abort execution of the enclave.
 *
 * Mark the enclave as aborting. This blocks future enclave entry calls. The
 * enclave continues to execute until all threads exit the enclave.
 */
void oe_abort(void);

/**
 * Called whenever an assertion fails.
 *
 * This internal function is called when the expression of the oe_assert()
 * macro evaluates to zero. For example:
 *
 *     oe_assert(x > y);
 *
 * If the expression evaluates to zero, this function is called with the
 * string representation of the expression as well as the file, the line, and
 * the function name where the macro was expanded.
 *
 * The __oe_assert_fail() function performs a host call to print a message
 * and then calls oe_abort().
 *
 * @param expr The argument of the oe_assert() macro.
 * @param file The name of the file where oe_assert() was invoked.
 * @param line The line number where oe_assert() was invoked.
 * @param func The name of the function that invoked oe_assert().
 *
 */
void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

#ifndef NDEBUG
#define oe_assert(EXPR)                                                \
    do                                                                 \
    {                                                                  \
        if (!(EXPR))                                                   \
            __oe_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define oe_assert(EXPR)
#endif

/**
 * Get a report signed by the enclave platform for use in attestation.
 *
 * This function creates a report to be used in local or remote attestation. The
 * report shall contain the data given by the **reportData** parameter.
 *
 * If the *reportBuffer* is NULL or *reportSize* parameter is too small,
 * this function returns OE_BUFFER_TOO_SMALL.
 *
 * @param flags Specifying default value (0) generates a report for local
 * attestation. Specifying OE_REPORT_FLAGS_REMOTE_ATTESTATION generates a
 * report for remote attestation.
 * @param reportData The report data that will be included in the report.
 * @param reportDataSize The size of the **reportData** in bytes.
 * @param optParams Optional additional parameters needed for the current
 * enclave type. For SGX, this can be sgx_target_info_t for local attestation.
 * @param optParamsSize The size of the **optParams** buffer.
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
oe_result_t oe_get_report(
    uint32_t flags,
    const uint8_t* reportData,
    size_t reportDataSize,
    const void* optParams,
    size_t optParamsSize,
    uint8_t* reportBuffer,
    size_t* reportBufferSize);

/**
 * Parse an enclave report into a standard format for reading.
 *
 * @param report The buffer containing the report to parse.
 * @param reportSize The size of the **report** buffer.
 * @param parsedReport The **oe_report_t** structure to populate with the report
 * properties in a standard format. The *parsedReport* holds pointers to fields
 * within the supplied *report* and must not be used beyond the lifetime of the
 * *report*.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t reportSize,
    oe_report_t* parsedReport);

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
 * @param parsedReport Optional **oe_report_t** structure to populate with the
 * report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t reportSize,
    oe_report_t* parsedReport);

typedef enum _oe_seal_policy {
    OE_SEAL_POLICY_UNIQUE = 1,
    OE_SEAL_POLICY_PRODUCT = 2,
    __OE_SEAL_POLICY_MAX = OE_ENUM_MAX,
} oe_seal_policy_t;

/**
* Get a symmetric encryption key derived from the specified policy and coupled
* to the enclave platform.
*
* @param sealPolicy The policy for the identity properties used to derive the
* seal key.
* @param keyBuffer The buffer to write the resulting seal key to.
* @param keyBufferSize The size of the **keyBuffer** buffer. If this is too
* small, this function sets it to the required size and returns
* OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
* to keyBuffer is set to it.
* @param keyInfo Optional buffer for the enclave-specific key information which
* can be used to retrieve the same key later, on a newer security version.
* @param keyInfoSize The size of the **keyInfo** buffer. If this is too small,
* this function sets it to the required size and returns OE_BUFFER_TOO_SMALL.
* When this function success, the number of bytes written to keyInfo is set to
* it.

* @retval OE_OK The seal key was successfully requested.
* @retval OE_INVALID_PARAMETER At least one parameter is invalid.
* @retval OE_BUFFER_TOO_SMALL The **keyBuffer** or **keyInfo** buffer is too
* small.
* @retval OE_UNEXPECTED An unexpected error happened.
*/
oe_result_t oe_get_seal_key_by_policy(
    oe_seal_policy_t sealPolicy,
    uint8_t* keyBuffer,
    size_t* keyBufferSize,
    uint8_t* keyInfo,
    size_t* keyInfoSize);

/**
* Get a symmetric encryption key from the enclave platform using existing key
* information.
*
* @param keyInfo The enclave-specific key information to derive the seal key
* with.
* @param keyInfoSize The size of the **keyInfo** buffer.
* @param keyBuffer The buffer to write the resulting seal key to. It will not
* be changed if this function fails.
* @param keyBufferSize The size of the **keyBuffer** buffer. If this is too
* small, this function sets it to the required size and returns
* OE_BUFFER_TOO_SMALL. When this function success, the number of bytes written
* to keyBuffer is set to it.
*
* @retval OE_OK The seal key was successfully requested.
* @retval OE_INVALID_PARAMETER At least one parameter is invalid.
* @retval OE_BUFFER_TOO_SMALL The **keyBuffer** buffer is too small.
* @retval OE_INVALID_CPUSVN **keyInfo** contains an invalid CPUSVN.
* @retval OE_INVALID_ISVSVN **keyInfo** contains an invalid ISVSVN.
* @retval OE_INVALID_KEYNAME **keyInfo** contains an invalid KEYNAME.
*/
oe_result_t oe_get_seal_key(
    const uint8_t* keyInfo,
    size_t keyInfoSize,
    uint8_t* keyBuffer,
    size_t* keyBufferSize);

/**
 * Obtains the enclave handle.
 *
 * This function returns the enclave handle for the current enclave. The
 * host obtains this handle by calling **oe_create_enclave()**, which
 * passes the enclave handle to the enclave during initialization. The
 * handle is an address inside the host address space.
 *
 * @returns the enclave handle.
 */
oe_enclave_t* oe_get_enclave(void);

OE_EXTERNC_END

#endif /* _OE_ENCLAVE_H */
