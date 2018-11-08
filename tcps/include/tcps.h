/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#define Tcps_InitializeStatus(xModule, xMethod) \
    oe_result_t uStatus = OE_OK; \
    Tcps_UInt32 uModule = xModule; \
    OE_UNUSED(uModule); \
    Tcps_GotoErrorIfBad(uStatus);
#define Tcps_BeginErrorHandling         Error:
#define Tcps_FinishErrorHandling        return uStatus;
#define Tcps_ReturnStatusCode           return uStatus & 0xFFFF0000L;
#define Tcps_ReturnErrorIfArgumentNull(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        return OE_INVALID_PARAMETER; \
    }
#define Tcps_ReturnErrorIfAllocFailed(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        return OE_OUT_OF_MEMORY; \
    }
#define Tcps_ReturnErrorIfTrue(xCondition, xStatus) \
    if (xCondition) \
    { \
        return xStatus; \
    }
#define Tcps_GotoError goto Error;
#define Tcps_GotoErrorIfTrue(xCondition, xStatus) \
    if (xCondition) \
    { \
        uStatus = xStatus; \
        goto Error; \
    }
#define Tcps_GotoErrorIfBad(xStatus) \
    if (xStatus != OE_OK) \
    { \
        goto Error; \
    }
#define Tcps_GotoErrorIfAllocFailed(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        uStatus = OE_OUT_OF_MEMORY; \
        goto Error; \
    }
#define Tcps_GotoErrorWithStatus(xStatus) \
    uStatus = xStatus; \
    goto Error;
#define Tcps_GotoErrorIfNull(xArg, xStatus) \
    if (xArg == Tcps_Null) \
    { \
        uStatus = (uStatus & 0x0000FFFF) | xStatus; \
        goto Error; \
    }
#define Tcps_Trace(x,...) ((Tcps_Void)0)
#define Tcps_P_Thread_WasTerminationRequested() Tcps_False

/* Types. */
typedef unsigned char       Tcps_Boolean;
typedef unsigned int        Tcps_UInt32;
typedef const char*         Tcps_ConstStringA;
typedef void                Tcps_Void;

/* Values. */
#define Tcps_Null                       (Tcps_Void*)0
#define Tcps_False                      0
#define Tcps_True                       (!Tcps_False)

typedef enum {
    Tcps_TraceLevelError            = 0x00000020,
    Tcps_TraceLevelWarning          = 0x00000010,
    Tcps_TraceLevelDebug            = 0x00000002,
} Tcps_TraceLevel;

#define Tcps_Module_Client_t           0x00000402
#define Tcps_Module_Helper_u           0x00000403
#define Tcps_Module_Helper_t           0x00000404

#ifndef TCPS_VERIFY
# if !defined(NDEBUG)
#  define TCPS_VERIFY                   assert
# else
#  define TCPS_VERIFY(_exp)             ((_exp) ? Tcps_True : Tcps_False)
# endif
#endif

/* Copy a string into a fixed size buffer.  Zero the buffer to prevent
 * leaking any extra data out of the TEE.
 */
#define COPY_MEMORY_BUFFER_FROM_STRING(buff, str) \
    memset((buff), 0, sizeof(buff)); \
    strcpy_s((buff), sizeof(buff), (str));

#define COPY_MEMORY_BUFFER(dest, src, srcLen) \
    if ((srcLen) < sizeof((dest))) { \
        memset((dest) + (srcLen), 0, sizeof(dest) - (srcLen)); \
    } \
    memcpy((dest), (src), (srcLen));

#define COPY_BUFFER_FROM_STRING(buff, str) \
    memset((buff).buffer, 0, sizeof((buff).buffer)); \
    strcpy_s((buff).buffer, sizeof((buff).buffer), (str));

#define COPY_BUFFER(dest, src, srcLen) \
    if ((srcLen) < sizeof((dest).buffer)) { \
        memset((dest).buffer + (srcLen), 0, sizeof((dest).buffer) - (srcLen)); \
    } \
    memcpy((dest).buffer, (src), (srcLen));

#if defined(__GNUC__)
#define TCPS_DEPRECATED(FUNC, MSG) FUNC __attribute__((deprecated(MSG)))
#elif defined(_MSC_VER)
#define TCPS_DEPRECATED(FUNC, MSG) __declspec(deprecated(MSG)) FUNC
#else
#define TCPS_DEPRECATED(FUNC, MSG) FUNC
#endif

#if defined(OE_SIMULATE_OPTEE) || defined(_ARM_)
# define OE_ENCLAVE_TYPE_DEFAULT OE_ENCLAVE_TYPE_TRUSTZONE
#else
# define OE_ENCLAVE_TYPE_DEFAULT OE_ENCLAVE_TYPE_SGX
#endif
