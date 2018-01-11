#ifndef _OE_CALLS_H
#define _OE_CALLS_H

#ifdef __OE_NEED_TIME_CALLS
# include <sys/time.h>
# include <time.h>
#endif

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

#define __OE_ECALL_BASE ((int)0x00FFFFFF)
#define __OE_OCALL_BASE ((int)0x00FFFFFF)

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** Define the OE_ARG_FLAGS for this platform.
**
**==============================================================================
*/

/* Causes enclave to use GS segment register rather than FS segment register */
#define OE_ARG_FLAG_GS 1

#if defined(__linux__)
# define OE_ARG_FLAGS OE_ARG_FLAG_GS
#elif define(_WIN32)
# define OE_ARG_FLAGS 0
#endif

/*
**==============================================================================
**
** OE_Code
**
**     The code parameter for OE_ECall() and OE_OCall()
**
**==============================================================================
*/

typedef enum _OE_Code
{
    OE_CODE_NONE  = 0,
    OE_CODE_ECALL = 1,
    OE_CODE_ERET  = 2,
    OE_CODE_OCALL = 3,
    OE_CODE_ORET  = 4
}
OE_Code;

/*
**==============================================================================
**
** ECN_Func
**
**     The func parameter for OE_ECall() and OE_OCall()
**
**==============================================================================
*/

typedef enum _OE_Func
{
    OE_FUNC_DESTRUCTOR         = 0x01000000,
    OE_FUNC_CALL_ENCLAVE       = 0x02000000,
    OE_FUNC_CALL_HOST          = 0x03000000,
    OE_FUNC_INIT_QUOTE         = 0x04000000,
    OE_FUNC_THREAD_WAKE        = 0x05000000,
    OE_FUNC_THREAD_WAIT        = 0x06000000,
    OE_FUNC_THREAD_WAKE_WAIT   = 0x07000000,
    OE_FUNC_MALLOC             = 0x08000000,
    OE_FUNC_FREE               = 0x09000000,
    OE_FUNC_PUTS               = 0x0A000000,
    OE_FUNC_PUTCHAR            = 0x0B000000,
    OE_FUNC_PRINT              = 0x0C000000,
    OE_FUNC_STRFTIME           = 0x0D000000,
    OE_FUNC_GETTIMEOFDAY       = 0x0E000000,
    OE_FUNC_CLOCK_GETTIME      = 0x0F000000,
    OE_FUNC_NANOSLEEP          = 0x10000000,
}
OE_Func;

/*
**==============================================================================
**
** OE_MakeArg()
**
**     Form the first argument to OE_Main(), which consists of flags, a code,
**     and a function number.
**
**==============================================================================
*/

OE_INLINE uint64_t OE_MakeArg(
    uint16_t flags,
    OE_Code code,
    OE_Func func)
{
    /* [ FLAGS:16, CODE:16, FUNC:32 ] */
    return ((uint64_t)flags << 48) | ((uint64_t)code << 32) | ((uint64_t)func);
}

/*
**==============================================================================
**
** OE_GetArgFlags()
**
**==============================================================================
*/

OE_INLINE uint16_t OE_GetArgFlags(uint64_t arg1)
{
    return (uint16_t)((0xFFFF000000000000 & arg1) >> 48);
}

/*
**==============================================================================
**
** OE_GetArgCode()
**
**==============================================================================
*/

OE_INLINE OE_Code OE_GetArgCode(uint64_t arg1)
{
    return (OE_Code)((0x0000FFFF00000000 & arg1) >> 32);
}

/*
**==============================================================================
**
** OE_GetArgFunc()
**
**==============================================================================
*/

OE_INLINE OE_Func OE_GetArgFunc(uint64_t arg1)
{
    return (OE_Func)(0x00000000FFFFFFFF & arg1);
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
}
OE_CallEnclaveArgs;

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
    char func[];
}
OE_CallHostArgs;

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
}
OE_ThreadWakeWaitArgs;

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
}
OE_InitQuoteArgs;

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
}
OE_StrftimeArgs;
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
    struct timeval *tv;
    struct timeval tvbuf;
    struct timezone *tz;
    uint64_t tzbuf[2];
}
OE_GettimeofdayArgs;
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
}
OE_ClockgettimeArgs;
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
}
OE_NanosleepArgs;
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
}
OE_PrintArgs;

OE_EXTERNC_END

#endif /* _OE_CALLS_H */
