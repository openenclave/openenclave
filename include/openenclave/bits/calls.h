// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CALLS_H
#define _OE_CALLS_H

#ifdef __OE_NEED_TIME_CALLS
#include <sys/time.h>
#include <time.h>
#endif

#include <openenclave/bits/cpuid.h>
#include <openenclave/defs.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

#define __OE_ECALL_BASE ((int)0x00FFFFFF)
#define __OE_OCALL_BASE ((int)0x00FFFFFF)

#define OE_MAX_ECALLS 1024
#define OE_MAX_OCALLS 1024

OE_EXTERNC_BEGIN

typedef struct _OE_Enclave OE_Enclave;

typedef void (*OE_ECallFunction)(uint64_t argIn, uint64_t* argOut);

typedef void (*OE_OCallFunction)(uint64_t argIn, uint64_t* argOut);

/*
**==============================================================================
**
** The flags parameter for OE_OCall()
**
** Flags stack with the ones on the current thread (i.e., are or'd together)
** for the duration of the ocall.
**
**==============================================================================
*/

/* Disallow OCALLs to call back into enclave with an ECALL */
#define OE_OCALL_FLAG_NOT_REENTRANT (1u << 0)

/*
**==============================================================================
**
** OE_Code
**
**     The code parameter for OE_ECall() and OE_OCall()
**
**==============================================================================
*/

typedef enum _OE_Code {
    OE_CODE_NONE = 0,
    OE_CODE_ECALL = 1,
    OE_CODE_ERET = 2,
    OE_CODE_OCALL = 3,
    OE_CODE_ORET = 4
} OE_Code;

/*
**==============================================================================
**
** OE_Func
**
**     The func parameter for OE_ECall() and OE_OCall()
**
**==============================================================================
*/

typedef enum _OE_Func {
    OE_FUNC_DESTRUCTOR = 0x01000000,
    OE_FUNC_INIT_ENCLAVE = 0x01800000,
    OE_FUNC_CALL_ENCLAVE = 0x02000000,
    OE_FUNC_CALL_HOST = 0x03000000,
    OE_FUNC_INIT_QUOTE = 0x04000000,
    OE_FUNC_GET_SGX_REPORT = 0x04100000,
    OE_FUNC_GET_REMOTE_REPORT = 0x04200000,
    OE_FUNC_THREAD_WAKE = 0x05000000,
    OE_FUNC_THREAD_WAIT = 0x06000000,
    OE_FUNC_THREAD_WAKE_WAIT = 0x07000000,
    OE_FUNC_MALLOC = 0x08000000,
    OE_FUNC_REALLOC = 0x08800000,
    OE_FUNC_FREE = 0x09000000,
    OE_FUNC_PUTS = 0x0A000000,
    OE_FUNC_PUTCHAR = 0x0B000000,
    OE_FUNC_PRINT = 0x0C000000,
    OE_FUNC_STRFTIME = 0x0D000000,
    OE_FUNC_GETTIMEOFDAY = 0x0E000000,
    OE_FUNC_CLOCK_GETTIME = 0x0F000000,
    OE_FUNC_NANOSLEEP = 0x10000000,
    OE_FUNC_VIRTUAL_EXCEPTION_HANDLER = 0x20000000,
} OE_Func;

#define OE_EXCEPTION_CONTINUE_SEARCH 0x0
#define OE_EXCEPTION_CONTINUE_EXECUTION 0xFFFFFFFF

/*
**==============================================================================
**
** OE_MakeCallArg1()
**
**     Form the 'arg1' parameter to both OE_Enter() and OE_Exit(). This
**     parameter is a 64-bit integer that contains:
**
**         code -- indicating whether ECALL, OCALL, ERET, or ORET
**         func -- the number of the function being called
**         flags -- any bit flags
**
**==============================================================================
*/

OE_INLINE uint64_t OE_MakeCallArg1(OE_Code code, OE_Func func, uint16_t flags)
{
    /* [ FLAGS:16, CODE:16, FUNC:32 ] */
    return ((uint64_t)code << 48) | ((uint64_t)func << 16) | ((uint64_t)flags);
}

/*
**==============================================================================
**
** OE_GetCodeFromCallArg1()
**
**==============================================================================
*/

OE_INLINE OE_Code OE_GetCodeFromCallArg1(uint64_t arg)
{
    return (OE_Code)((0xFFFF000000000000 & arg) >> 48);
}

/*
**==============================================================================
**
** OE_GetFuncFromCallArg1()
**
**==============================================================================
*/

OE_INLINE OE_Func OE_GetFuncFromCallArg1(uint64_t arg)
{
    return (OE_Func)((0x0000FFFFFFFF0000 & arg) >> 16);
}

/*
**==============================================================================
**
** OE_GetFlagsFromCallArg1()
**
**==============================================================================
*/

OE_INLINE uint16_t OE_GetFlagsFromCallArg1(uint64_t arg)
{
    return (uint16_t)(0x000000000000FFFF & arg);
}

/*
**==============================================================================
**
** OE_CallEnclaveArgs
**
**==============================================================================
*/

typedef void (*OE_EnclaveFunc)(void* args);

typedef struct OE_CallEnclaveArgs
{
    uint64_t func;
    uint64_t vaddr;
    void* args;
    OE_Result result;
} OE_CallEnclaveArgs;

/*
**==============================================================================
**
** OE_CallHostArgs
**
**==============================================================================
*/

typedef void (*OE_HostFunc)(void* args);

typedef struct OE_CallHostArgs
{
    void* args;
    OE_Result result;
    OE_ZERO_SIZED_ARRAY char func[];
} OE_CallHostArgs;

/*
**==============================================================================
**
** OE_ThreadWakeWaitArgs
**
**==============================================================================
*/

typedef struct _OE_ThreadWakeWaitArgs
{
    const void* waiter_tcs;
    const void* self_tcs;
} OE_ThreadWakeWaitArgs;

/*
**==============================================================================
**
** OE_InitQuoteArgs
**
**==============================================================================
*/

typedef struct _OE_InitQuoteArgs
{
    OE_Result result;
    SGX_TargetInfo targetInfo;
    SGX_EPIDGroupID epidGroupID;
} OE_InitQuoteArgs;

/*
**==============================================================================
**
** OE_GetSGXReportArgs
**
**==============================================================================
*/

typedef struct _OE_GetSGXReportArgs
{
    const void* reportData;
    uint32_t reportDataSize;

    const void* targetInfo;
    uint32_t targetInfoSize;

    void* report;
    uint32_t* reportSize;
} OE_GetSGXReportArgs;

/*
**==============================================================================
**
** OE_GetReportArgs
**
**==============================================================================
*/

typedef struct _OE_GetRemoteReportArgs
{
    uint8_t reportData[sizeof(SGX_ReportData)]; /* in */
    uint32_t reportDataSize;                    /* in */

    OE_Result result; /* out */

    uint32_t reportBufferSize; /* in-out */
    uint8_t reportBuffer[1];   /* out */
} OE_GetRemoteReportArgs;

/*
**==============================================================================
**
** OE_StrftimeArgs
**
**     size_t strftime(
**         char *str,
**         size_t max,
**         const char *format,
**         const struct tm *tm);
**
**==============================================================================
*/

#ifdef __OE_NEED_TIME_CALLS
typedef struct _OE_StrftimeArgs
{
    size_t ret;
    char str[256];
    char format[256];
    struct tm tm;
} OE_StrftimeArgs;
#endif

/*
**==============================================================================
**
** OE_GettimeofdayArgs
**
**     int gettimeofday(struct timeval *tv, struct timezone *tz)
**
**==============================================================================
*/

#ifdef __OE_NEED_TIME_CALLS
typedef struct _OE_GettimeofdayArgs
{
    int ret;
    struct timeval* tv;
    struct timeval tvbuf;
    struct timezone* tz;
    uint64_t tzbuf[2];
} OE_GettimeofdayArgs;
#endif

/*
**==============================================================================
**
** OE_ClockgettimeArgs
**
**     int clock_gettime(clockid_t clk_id, struct timespec *tp);
**
**==============================================================================
*/

#ifdef __OE_NEED_TIME_CALLS
typedef struct _OE_ClockgettimeArgs
{
    int ret;
    clockid_t clk_id;
    struct timespec* tp;
    struct timespec tpbuf;
} OE_ClockgettimeArgs;
#endif

/*
**==============================================================================
**
** OE_NanosleepArgs
**
**     int nanosleep(const struct timespec *req, struct timespec *rem);
**
**==============================================================================
*/

#ifdef __OE_NEED_TIME_CALLS
typedef struct _OE_NanosleepArgs
{
    int ret;
    const struct timespec* req;
    struct timespec reqbuf;
    struct timespec* rem;
    struct timespec rembuf;
} OE_NanosleepArgs;
#endif

/*
**==============================================================================
**
** OE_PrintArgs
**
**     Print 'str' to stdout (device == 0) or stderr (device == 1).
**
**==============================================================================
*/

typedef struct _OE_PrintArgs
{
    int device;
    char* str;
} OE_PrintArgs;

/*
**==============================================================================
**
** OE_ReallocArgs
**
**     void* realloc(void* ptr, size_t size)
**
**==============================================================================
*/

typedef struct _OE_ReallocArgs
{
    void* ptr;
    size_t size;
} OE_ReallocArgs;

/*
**==============================================================================
**
** OE_InitEnclaveArgs
**
**     Runtime state to initialize enclave state with, includes
**     - First 8 leaves of CPUID for enclave emulation
**
**==============================================================================
*/

typedef struct _OE_InitEnclaveArgs
{
    uint32_t cpuidTable[OE_CPUID_LEAF_COUNT][OE_CPUID_REG_COUNT];
} OE_InitEnclaveArgs;

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
 * @param argIn The input argument passed to the function.
 * @param argOut The output argument passed back from the function.
 * @param ocall_flags Additional flags for the duration of this ocall, such as
 *              OE_OCALL_FLAG_NOT_REENTRANT.
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
    uint64_t* argOut,
    uint32_t ocall_flags);
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
OE_Result OE_RegisterECall(uint32_t func, OE_ECallFunction ecall);

/**
 * Registers a low-level OCALL function.
 *
 * TODO: Redesign this, this needs to be enclave-specific.
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
OE_Result OE_RegisterOCall(uint32_t func, OE_OCallFunction ocall);

OE_EXTERNC_END

#endif /* _OE_CALLS_H */
