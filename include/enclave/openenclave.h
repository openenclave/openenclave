#ifndef _ENCLAVE_OPENENCLAVE_H
#define _ENCLAVE_OPENENCLAVE_H

#include "oecommon/defs.h"
#include "oecommon/types.h"
#include "oecommon/result.h"
#include "oecommon/thread.h"
#include "oecommon/typeinfo.h"
#include "oecommon/atomic.h"
#include "oecommon/sha.h"

OE_EXTERNC_BEGIN

#define OE_BUILD_ENCLAVE

#define OE_ECALL_SECTION __attribute__((section (".ecall")))

#ifdef __cplusplus
# define OE_ECALL OE_EXTERNC OE_ECALL_SECTION
#else
# define OE_ECALL OE_ECALL_SECTION
#endif

/* Returns TRUE if memory is inside the enclave */
oe_bool OE_IsWithinEnclave(
    const void* ptr,
    oe_size_t size);

/* Returns TRUE if memory is outside the enclave */
oe_bool OE_IsOutsideEnclave(
    const void* ptr,
    oe_size_t size);

/** 
 * Call a host function.
 */
OE_Result OE_CallHost(
    const char *func,
    void *args);

/*!
 * Call the function with the given number
 */
OE_Result __OE_OCall(
    int func,
    oe_uint64_t argIn,
    oe_uint64_t* argOut);

typedef struct _OE_EnclaveReportData
{
    unsigned char field[64];
} 
OE_EnclaveReportData;

OE_Result OE_GetReportForRemoteAttestation(
    const OE_EnclaveReportData *reportData,
    void *report,
    oe_size_t* reportSize);

void __OE_HandleMain(
    oe_uint64_t arg1,
    oe_uint64_t arg2,
    oe_uint64_t cssa,
    void* tcs);

int OE_PutsUint64(
    oe_uint64_t x);

/*
**==============================================================================
**
** String functions:
**
**==============================================================================
*/

oe_size_t OE_Strlen(const char* s);

oe_size_t OE_Wcslen(const oe_wchar_t* s);

int OE_Strcmp(const char* s1, const char* s2);

int OE_Wcscmp(const oe_wchar_t* s1, const oe_wchar_t* s2);

char *OE_Strcpy(char* dest, const char* src);

void *OE_Memcpy(void *dest, const void *src, oe_size_t n);

void *OE_Memset(void *s, int c, oe_size_t n);

int OE_Memcmp(const void *s1, const void *s2, oe_size_t n);

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

void *OE_Malloc(oe_size_t size);

void OE_Free(void *ptr);

void *OE_Calloc(oe_size_t nmemb, oe_size_t size);

void *OE_Realloc(void *ptr, oe_size_t size);

char* OE_Strdup(const char* s);

void *OE_Memalign(oe_size_t alignment, oe_size_t size);

/*
**==============================================================================
**
** Host heap memory allocation:
**
**==============================================================================
*/

void* OE_HostMalloc(oe_size_t size);

void* OE_HostCalloc(oe_size_t nmemb, oe_size_t size);

void OE_HostFree(void* ptr);

char* OE_HostStrdup(const char* str);

/*
**==============================================================================
**
** Var-args list:
**
**==============================================================================
*/

typedef __builtin_va_list oe_va_list;

#define oe_va_start(ap, last) __builtin_va_start((ap), last)

#define oe_va_end __builtin_va_end

#define oe_va_arg __builtin_va_arg

#define oe_va_copy(dst, src) __builtin_va_copy((dst), (src))

OE_EXTERNC_END

#endif /* _ENCLAVE_OPENENCLAVE_H */
