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
 * \param ptr pointer to buffer
 * \param size size of buffer
 *
 * \retval true if buffer is strictly within the enclave
 * \retval false if any portion of the buffer falls outside the enclave
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
 * \param ptr pointer to buffer
 * \param size size of buffer
 *
 * \retval true if buffer is strictly outside the enclave
 * \retval false if any portion of the buffer falls within the enclave
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
 * \param func name of the host function that will be called
 * \param args arguments to be passed to the host function
 *
 * \retval OE_OK on success
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

int OE_PutsUint64(
    uint64_t x);

/*
**==============================================================================
**
** String functions:
**
**==============================================================================
*/

size_t OE_Strlen(const char* s);

size_t OE_Wcslen(const wchar_t* s);

int OE_Strcmp(const char* s1, const char* s2);

int OE_Wcscmp(const wchar_t* s1, const wchar_t* s2);

char *OE_Strcpy(char* dest, const char* src);

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

/*
**==============================================================================
**
** Functions for writing to the host's console.
**
**==============================================================================
*/

int OE_HostPuts(const char* str);

int OE_HostPutchar(int c);

/*
**==============================================================================
**
** Heap memory allocation:
**
**==============================================================================
*/

void *OE_Malloc(size_t size);

void OE_Free(void *ptr);

void *OE_Calloc(size_t nmemb, size_t size);

void *OE_Realloc(void *ptr, size_t size);

char* OE_Strdup(const char* s);

void *OE_Memalign(size_t alignment, size_t size);

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

OE_EXTERNC_END

#endif /* _OE_ENCLAVE_H */
