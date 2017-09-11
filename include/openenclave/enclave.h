/** \file enclave.h */
#ifndef _OE_ENCLAVE_H
#define _OE_ENCLAVE_H

#include "defs.h"
#include "types.h"
#include "result.h"
#include "thread.h"
#include "typeinfo.h"
#include "atomic.h"
#include "sha.h"

OE_EXTERNC_BEGIN

#ifndef OE_BUILD_ENCLAVE
# define OE_BUILD_ENCLAVE
#endif

#define OE_ECALL_SECTION __attribute__((section (".ecall")))

#ifdef __cplusplus
# define OE_ECALL OE_EXTERNC OE_EXPORT OE_ECALL_SECTION
#else
# define OE_ECALL OE_EXPORT OE_ECALL_SECTION
#endif

#define OE_REPORT_DATA_SIZE 64

#define OE_MAX_ECALLS 1024
#define OE_MAX_OCALLS 1024

typedef void (*OE_ECallFunction)(
    uint64_t argIn,
    uint64_t* argOut);

/**
 * The enclave constructor function.
 *
 * The enclave constructor function is called after enclave creation when
 * the enclave is entered for the first time. Enclaves may optionally include
 * a definition to this function.
 *
 */
OE_EXPORT void OE_Constructor(void);

/**
 * The enclave destructor function.
 *
 * The enclave destructor function is called when an enclave is terminated by
 * the host. Enclaves may optionally include a definition to this function.
 *
 */
OE_EXPORT void OE_Destructor(void);

/**
 * Perform a low-level host function call (OCALL).
 *
 * This function performs a low-level host function call by invoking the 
 * function indicated by the **func** parameter. The host defines and 
 * registers a corresponding function with the following signature.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut); 
 *
 * The meaning of the **argIn** arg **argOut** parameters is defined by the
 * implementer of the function and either may be null.
 *
 * OpenEnclave uses this interface to implement internal calls. Enclave 
 * application developers are encouraged to use OE_CallHost() instead.
 *
 * At the software layer, this function sends an **OCALL** message to the 
 * enclave and waits for an **ORET** message. Note that the OCALL implementation
 * may call back into the enclave (an ECALL) before returning.
 *
 * At the hardware layer, this function executes the **ENCLU.EEXIT**
 * instruction to exit the enclave. When the host returns from the OCALL, 
 * it executes the **ENCLU.EENTER** instruction to reenter the enclave and
 * resume execution.
 *
 * Note that the return value only indicates whether the OCALL was called 
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
OE_Result OE_OCall(
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut);

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
 * This function is implemented using the low-level **OE_ECall()** interface
 * where the function number is given by the **OE_FUNC_CALL_HOST** constant.
 *
 * Note that the return value of this function only indicates the success of
 * the call and not of the underlying function. The OCALL implementation must 
 * define its own error reporting scheme based on **args**.
 *
 * @param func The name of the enclave function that will be called.
 * @param args The arguments to be passed to the enclave function.
 *
 * @returns This function return **OE_OK** on success.
 *
 */
OE_Result OE_CallHost(
    const char *func,
    void *args);

/**
 * Registers a low-level ECALL function.
 *
 * This function registers a low-level ECALL function that may be called
 * from the host by the **OE_ECall()** function. The registered function
 * has the following prototype.
 *
 *     void (*)(uint64_t argIn, uint64_t* argOut);
 *
 * This interface is intended mainly for internal use and developers are
 * encouraged to use the high-level interface instead.
 *
 * @param func The number of the function to be called.
 * @param ecall The address of the function to be called.
 *
 * @retval OE_OK The function was successful.
 * @retval OE_OUT_OF_RANGE The function number was greater than OE_MAX_ECALLS.
 * @retval OE_ALREADY_IN_USE The function number is already in use.
 *
 */
OE_Result OE_RegisterECall(
    uint32_t func,
    OE_ECallFunction ecall);

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
 * @retval false At least some part of the buffer is outside the enclave.
 *
 */
bool OE_IsWithinEnclave(
    const void* ptr,
    size_t size);

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
 * @retval false At least some part of the buffer is within the enclave.
 *
 */
bool OE_IsOutsideEnclave(
    const void* ptr,
    size_t size);

/**
 * Get a report for use in remote attestation.
 *
 * This function is experimental and is likely to change.
 */
OE_Result OE_GetReportForRemoteAttestation(
    const uint8_t reportData[OE_REPORT_DATA_SIZE],
    void *report,
    size_t* reportSize);

/**
 * Enclave implementation of standard strlen() function.
 *
 * Refer to documentation for strlen() function.
 */
size_t OE_Strlen(const char* s);

/**
 * Enclave implementation of standard strcmp() function.
 *
 * Refer to documentation for strcmp() function.
 */
int OE_Strcmp(const char* s1, const char* s2);

/**
 * Enclave implementation of standard strlcpy() function.
 *
 * Refer to documentation for strlcpy() function.
 */
size_t OE_Strlcpy(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of standard strlcat() function.
 *
 * Refer to documentation for strlcat() function.
 */
size_t OE_Strlcat(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of standard memcpy() function.
 *
 * Refer to documentation for memcpy() function.
 */
void *OE_Memcpy(void *dest, const void *src, size_t n);

/**
 * Enclave implementation of standard memset() function.
 *
 * Refer to documentation for memset() function.
 */
void *OE_Memset(void *s, int c, size_t n);

/**
 * Enclave implementation of standard memcmp() function.
 *
 * Refer to documentation for memcmp() function.
 */
int OE_Memcmp(const void *s1, const void *s2, size_t n);

/**
 * Produce output according to a given format string.
 *
 * This function is similar to vsnprintf() but has limited support for format
 * types. It only supports the following without width specifiers.
 *     - "%s"
 *     - "%u"
 *     - "%d"
 *     - "%x"
 *     - "%lu"
 *     - "%ld"
 *     - "%lx"
 *     - "%zu"
 *     - "%zd"
 *     - "%p"
 *
 * @param str Write output to this string
 * @param size The size of **str** parameter.
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that would be written excluding the 
 * zero-terminator. If this value is greater or equal to **size**, then the 
 * string was truncated.
 *
 */
int OE_Vsnprintf(char* str, size_t size, const char* fmt, OE_va_list ap);

/**
 * Produce output according to a given format string.
 *
 * This function is similar to snprintf() but has limited support for format
 * types. See OE_Vsnprintf() for details on these limits.
 *
 * @param str Write output to this string.
 * @param size The size of **str** parameter.
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that would be written excluding the 
 * zero-terminator. If this value is greater or equal to **size**, then the 
 * string was truncated.
 *
 */
OE_PRINTF_FORMAT(3, 4)
int OE_Snprintf(char* str, size_t size, const char* fmt, ...);

/**
 * Print formatted characters to the host's console.
 *
 * This function writes formatted characters to the host console. Is is based
 * on OE_Vsnprintf(), which has limited support for format types.
 *
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that were written.
 *
 */
OE_PRINTF_FORMAT(1, 2)
int OE_HostPrintf(const char* fmt, ...);

/**
 * Allocates space on the stack frame of the caller.
 *
 * This function allocates **size** bytes of space on the stack frame of the 
 * caller. The returned address will be a multiple of **alignment** (if
 * non-zero). The allocated space is automatically freed when the calling 
 * function returns. If the stack overflows, the behavior is undefined.
 *
 * @param size The number of bytes to allocate.
 * @param alignment The alignment requirement (see above).
 *
 * @returns Returns the address of the allocated space.
 *
 */
OE_ALWAYS_INLINE OE_INLINE void *OE_StackAlloc(
    size_t size, 
    size_t alignment)
{
    void* ptr = __builtin_alloca(size + alignment);

    if (alignment)
        ptr = (void*)(((uint64_t)ptr + alignment - 1) / alignment * alignment);

    return ptr;
}

void* OE_HostMalloc(size_t size);

void* OE_HostCalloc(size_t nmemb, size_t size);

void OE_HostFree(void* ptr);

char* OE_HostStrdup(const char* str);

/**
 * Abort execution by causing and illegal instruction exception.
 *
 * This function aborts execution by executing the UD2 instruction.
 */
void OE_Abort(void);

/**
 * Enclave implementation of the standard Unix sbrk() system call.
 *
 * This function provides an enclave equivalent to the sbrk() system call.
 * It increments the current end of the heap by **increment** bytes. Calling
 * OE_Sbrk() with an increment of 0, returns the current end of the heap.
 *
 * @param increment Number of bytes to increment the heap end by.
 *
 * @returns The old end of the heap (before the increment) or zero if there
 * are less than **increment** bytes remaining on the heap.
 *
 */
void* OE_Sbrk(ptrdiff_t increment);

void __OE_AssertFail(
    const char *expr,
    const char *file,
    int line,
    const char *func);

#define OE_Assert(EXPR) \
    do \
    { \
        if (!(EXPR)) \
            __OE_AssertFail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } \
    while (0)

OE_EXTERNC_END

#endif /* _OE_ENCLAVE_H */
