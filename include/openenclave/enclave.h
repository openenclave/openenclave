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

typedef struct _OE_EnclaveReportData
{
    unsigned char field[64];
}
OE_EnclaveReportData;

/**
 * Check whether the given buffer is strictly within the enclave.
 *
 * Check whether the buffer given by the \b ptr and \b size parameters is 
 * strictly within the enclave's memory. If so, return true. If any
 * portion of the buffer lies outside the enclave's memory, return false.
 *
 * \param ptr The pointer pointer to buffer.
 * \param size The size of buffer
 *
 * \retval true The buffer is strictly within the enclave.
 * \retval false At least some part of the buffer is outside the enclave.
 *
 */
bool OE_IsWithinEnclave(
    const void* ptr,
    size_t size);

/**
 * Check whether the given buffer is strictly outside the enclave.
 *
 * Check whether the buffer given by the \b ptr and \b size parameters is 
 * strictly outside the enclave's memory. If so, return true. If any
 * portion of the buffer lies within the enclave's memory, return false.
 *
 * \param The ptr pointer to buffer.
 * \param The size size of buffer.
 *
 * \retval true The buffer is strictly outside the enclave.
 * \retval false At least some part of the buffer is within the enclave.
 *
 */
bool OE_IsOutsideEnclave(
    const void* ptr,
    size_t size);

/**
 * Perform an outside function call (or OCALL) into the host
 *
 * Call the host function named \b func, passing it the \b args parameter. The
 * host must provide a host function with the following signature.
 *
 *     OE_OCALL void MyHostFunction(void* args);
 *
 * The meaning of the \b args parameter is defined by the OCALL implementation
 * and might be null for some implementations.
 *
 * At the software layer, this function sends an \b OCALL message to the host 
 * and waits for an \b ORET message. Note that the OCALL implementation may 
 * call back into the enclave (an ECALL) before returning.
 *
 * At the hardware layer, this function executes the \b ENCLU.EEXIT instruction 
 * to leave the enclave and enter the host. When the host returns from the 
 * ECALL, it executes the \b ENCLU.EENTER instruction to reenter the enclave.
 *
 * Note that the return value only indicates whether the OCALL was called and
 * not whether it was successful. The OCALL implementation must define its own
 * error reporting scheme based on the \b args parameter.
 *
 * \param func The name of the host function that will be called.
 * \param args The arguments to be passed to the host function.
 *
 * \retval OE_OK The function was successful.
 * \retval OE_FAILED The function failed.
 *
 */
OE_Result OE_CallHost(
    const char *func,
    void *args);

OE_Result __OE_OCall(
    int func,
    uint64_t argIn,
    uint64_t* argOut);

OE_Result OE_GetReportForRemoteAttestation(
    const OE_EnclaveReportData *reportData,
    void *report,
    size_t* reportSize);

void __OE_HandleMain(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs);

/*
**==============================================================================
**
** String functions:
**
**==============================================================================
*/

size_t OE_Strlen(const char* s);

int OE_Strcmp(const char* s1, const char* s2);

size_t OE_Strlcpy(char* dest, const char* src, size_t size);

size_t OE_Strlcat(char* dest, const char* src, size_t size);

void *OE_Memcpy(void *dest, const void *src, size_t n);

void *OE_Memset(void *s, int c, size_t n);

int OE_Memcmp(const void *s1, const void *s2, size_t n);

/*
**==============================================================================
**
** Abort
**
**==============================================================================
*/

void OE_Abort(void);

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
 * \param str Write output to this string
 * \param size The size of \b str parameter.
 * \param fmt The limited printf style format.
 *
 * \returns The number of characters that would be written excluding the 
 * zero-terminator. If this value is greater or equal to \b size, then the 
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
 * \param str Write output to this string.
 * \param size The size of \b str parameter.
 * \param fmt The limited printf style format.
 *
 * \returns The number of characters that would be written excluding the 
 * zero-terminator. If this value is greater or equal to \b size, then the 
 * string was truncated.
 *
 */
OE_PRINTF_FORMAT(3, 4)
int OE_Snprintf(char* str, size_t size, const char* fmt, ...);

/*
**==============================================================================
**
** Functions for writing to the host's console.
**
**==============================================================================
*/

int OE_HostPuts(const char* str);

int OE_HostPrint(const char* str);

int OE_HostVprintf(const char* fmt, OE_va_list ap_);

/**
 * Print formatted characters to the host's console.
 *
 * This function writes formatted characters to the host console. Is is based
 * on OE_Vsnprintf(), which has limited support for format types.
 *
 * \param fmt The limited printf style format.
 *
 * \returns The number of characters that were written.
 *
 */
OE_PRINTF_FORMAT(1, 2)
int OE_HostPrintf(const char* fmt, ...);

int OE_HostPutchar(int c);

/**
 * Allocates space on the stack frame of the caller.
 *
 * This function allocates \b size bytes of space on the stack frame of the 
 * caller. The returned address will be a multiple of \b alignment (if
 * non-zero). The allocated space is automatically freed when the calling 
 * function returns. If the stack overflows, the behavior is undefined.
 *
 * \param size The number of bytes to allocate.
 * \param alignment The alignment requirement (see above).
 *
 * \returns Returns the address of the allocated space.
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

/*
**==============================================================================
**
** Host heap memory allocation:
**
**==============================================================================
*/

void* OE_HostMalloc(size_t size);

void* OE_HostCalloc(size_t nmemb, size_t size);

void OE_HostFree(void* ptr);

char* OE_HostStrdup(const char* str);

/*
**==============================================================================
**
** OE_Sbrk()
**
**==============================================================================
*/

void* OE_Sbrk(ptrdiff_t increment);

/*
**==============================================================================
**
** Assertion:
**
**==============================================================================
*/

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
