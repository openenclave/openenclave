#ifndef _ENCLAVE_OPENENCLAVE_H
#define _ENCLAVE_OPENENCLAVE_H

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include "openenclave/defs.h"
#include "openenclave/types.h"
#include "openenclave/result.h"
#include "openenclave/thread.h"
#include "openenclave/typeinfo.h"
#include "openenclave/atomic.h"
#include "openenclave/sha.h"

OE_EXTERNC_BEGIN

#define OE_ECALL_SECTION __attribute__((section (".ecall")))

#ifdef __cplusplus
# define OE_ECALL OE_EXTERNC OE_ECALL_SECTION
#else
# define OE_ECALL OE_ECALL_SECTION
#endif

/* Returns TRUE if memory is inside the enclave */
bool OE_IsWithinEnclave(
    const void* ptr,
    size_t size);

/* Returns TRUE if memory is outside the enclave */
bool OE_IsOutsideEnclave(
    const void* ptr,
    size_t size);

OE_Result OE_CallHost(
    const char *func,
    void *args);

OE_Result __OE_OCall(
    int func,
    uint64_t argIn,
    uint64_t* argOut);

typedef struct _OE_EnclaveReportData
{
    unsigned char field[64];
} 
OE_EnclaveReportData;

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

OE_EXTERNC_END

#endif /* _ENCLAVE_OPENENCLAVE_H */
