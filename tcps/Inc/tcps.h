/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

/* Define this to define TCPS defines in terms of OPC UA defines.
 * If you undefine this, you will need to add substitute defines.
 */
#undef USE_OPCUA

#ifdef USE_OPCUA
# include <opcua.h>
# include <opcua_debug.h>
# define Tcps_InitializeStatus                 OpcUa_InitializeStatus
# define Tcps_BeginErrorHandling               OpcUa_BeginErrorHandling
# define Tcps_FinishErrorHandling              OpcUa_FinishErrorHandling
# define Tcps_ReturnStatusCode                 OpcUa_ReturnStatusCode
# define Tcps_ReturnErrorIfArgumentNull        OpcUa_ReturnErrorIfArgumentNull
# define Tcps_ReturnErrorIfAllocFailed         OpcUa_ReturnErrorIfAllocFailed
# define Tcps_ReturnErrorIfTrue                OpcUa_ReturnErrorIfTrue
# define Tcps_GotoError                        OpcUa_GotoError
# define Tcps_GotoErrorIfTrue                  OpcUa_GotoErrorIfTrue
# define Tcps_GotoErrorIfBad                   OpcUa_GotoErrorIfBad
# define Tcps_GotoErrorWithStatus              OpcUa_GotoErrorWithStatus
# define Tcps_GotoErrorIfNull                  OpcUa_GotoErrorIfNull
# define Tcps_Trace                            OpcUa_Trace

# include <opcua_p_thread.h>
# define Tcps_P_Thread_WasTerminationRequested OpcUa_P_Thread_WasTerminationRequested
#else
# define Tcps_InitializeStatus(xModule, xMethod) \
    Tcps_StatusCode uStatus = Tcps_Good; \
    Tcps_UInt32 uModule = xModule; \
    TCPS_UNUSED(uModule); \
    Tcps_GotoErrorIfBad(uStatus);
# define Tcps_BeginErrorHandling         Error:
# define Tcps_FinishErrorHandling        return uStatus;
# define Tcps_ReturnStatusCode           return uStatus & 0xFFFF0000L;
# define Tcps_ReturnErrorIfArgumentNull(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        return Tcps_BadInvalidArgument; \
    }
# define Tcps_ReturnErrorIfAllocFailed(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        return Tcps_BadOutOfMemory; \
    }
# define Tcps_ReturnErrorIfTrue(xCondition, xStatus) \
    if (xCondition) \
    { \
        return xStatus; \
    }
# define Tcps_GotoError goto Error;
# define Tcps_GotoErrorIfTrue(xCondition, xStatus) \
    if (xCondition) \
    { \
        uStatus = (Tcps_StatusCode)((uStatus & 0x0000FFFF) | xStatus); \
        goto Error; \
    }
# define Tcps_IsBad(xCode) (((xCode) & 0x80000000) != 0)
# define Tcps_GotoErrorIfBad(xStatus) \
    if (Tcps_IsBad(xStatus)) \
    { \
        goto Error; \
    }
# define Tcps_GotoErrorIfAllocFailed(xArg) \
    if ((xArg) == Tcps_Null) \
    { \
        uStatus = (uStatus & 0x0000FFFF) | Tcps_BadOutOfMemory; \
        goto Error; \
    }
# define Tcps_GotoErrorWithStatus(xStatus) \
    uStatus = xStatus; \
    goto Error;
# define Tcps_GotoErrorIfNull(xArg, xStatus) \
    if (xArg == Tcps_Null) \
    { \
        uStatus = (uStatus & 0x0000FFFF) | xStatus; \
        goto Error; \
    }
# define Tcps_Trace(x,...) ((Tcps_Void)0)
# define Tcps_P_Thread_WasTerminationRequested() Tcps_False
#endif

#ifdef OpcUa_Alloc
# define TCPS_ALLOC                      OpcUa_Alloc
# define TCPS_FREE                       OpcUa_Free
# define TCPS_REALLOC                    OpcUa_ReAlloc
#else
# define TCPS_ALLOC(s)                   malloc(s)
# define TCPS_FREE(p)                    free(p)
# define TCPS_REALLOC(p, s)              realloc(p, s)
#endif
#define TCPS_ZERO(_p, _s)                memset(_p, 0x00, _s);

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
#ifdef OpcUa_BadUnexpectedError
    /* Define protocol-agnostic status codes in terms of OPC UA ones. */
    Tcps_Good                       = OpcUa_Good,
    Tcps_Bad                        = OpcUa_Bad,
    Tcps_BadUnexpectedError         = OpcUa_BadUnexpectedError,
    Tcps_BadInternalError           = OpcUa_BadInternalError,
    Tcps_BadOutOfMemory             = OpcUa_BadOutOfMemory,
    Tcps_BadResourceUnavailable     = OpcUa_BadResourceUnavailable,
    Tcps_BadCommunicationError      = OpcUa_BadCommunicationError,
    Tcps_BadTimeout                 = OpcUa_BadTimeout,
    Tcps_BadCertificateInvalid      = OpcUa_BadCertificateInvalid,
    Tcps_BadNotImplemented          = OpcUa_BadNotImplemented,
    Tcps_BadNoMatch                 = OpcUa_BadNoMatch,
    Tcps_BadDataLost                = OpcUa_BadDataLost,
    Tcps_BadInvalidArgument         = OpcUa_BadInvalidArgument,
    Tcps_BadConnectionRejected      = OpcUa_BadConnectionRejected,
    Tcps_BadDisconnect              = OpcUa_BadDisconnect,
    Tcps_BadInvalidState            = OpcUa_BadInvalidState,
    Tcps_BadOperationAbandoned      = OpcUa_BadOperationAbandoned,
    Tcps_BadRequestTooLarge         = OpcUa_BadRequestTooLarge,
#else
    /* Define protocol-agnostic status codes without reference to OPC UA. */
    Tcps_Good                       = (int)0x00000000,
    Tcps_Bad                        = (int)0x80000000,
    Tcps_BadUnexpectedError         = (int)0x80010000,
    Tcps_BadInternalError           = (int)0x80020000,
    Tcps_BadOutOfMemory             = (int)0x80030000,
    Tcps_BadResourceUnavailable     = (int)0x80040000,
    Tcps_BadCommunicationError      = (int)0x80050000,
    Tcps_BadTimeout                 = (int)0x800A0000,
    Tcps_BadCertificateInvalid      = (int)0x80120000,
    Tcps_BadNotImplemented          = (int)0x80400000,
    Tcps_BadNoMatch                 = (int)0x806F0000,
    Tcps_BadDataLost                = (int)0x809D0000,
    Tcps_BadInvalidArgument         = (int)0x80AB0000,
    Tcps_BadConnectionRejected      = (int)0x80AC0000,
    Tcps_BadDisconnect              = (int)0x80AD0000,
    Tcps_BadInvalidState            = (int)0x80AF0000,
    Tcps_BadOperationAbandoned      = (int)0x80B30000,
    Tcps_BadRequestTooLarge         = (int)0x80B80000,
#endif
} Tcps_StatusCode;

typedef enum {
#ifdef OPCUA_TRACE_LEVEL_DEBUG 
    Tcps_TraceLevelError            = OPCUA_TRACE_LEVEL_ERROR,
    Tcps_TraceLevelWarning          = OPCUA_TRACE_LEVEL_WARNING,
    Tcps_TraceLevelDebug            = OPCUA_TRACE_LEVEL_DEBUG,
#else
    Tcps_TraceLevelError            = 0x00000020,
    Tcps_TraceLevelWarning          = 0x00000010,
    Tcps_TraceLevelDebug            = 0x00000002,
#endif
} Tcps_TraceLevel;

#ifdef OpcUa_Module_Helper_t
# define Tcps_Module_Client_t           OpcUa_Module_Client
# define Tcps_Module_Helper_t           OpcUa_Module_Helper_t
# define Tcps_Module_Helper_u           OpcUa_Module_Helper_u
#else
# define Tcps_Module_Client_t           0x00000402
# define Tcps_Module_Helper_u           0x00000403
# define Tcps_Module_Helper_t           0x00000404
#endif

#ifndef TCPS_ASSERT
# define TCPS_ASSERT                    assert
#endif
#ifndef TCPS_VERIFY
# if !defined(NDEBUG)
#  define TCPS_VERIFY                   TCPS_ASSERT
# else
#  define TCPS_VERIFY(_exp)             ((_exp) ? Tcps_True : Tcps_False)
# endif
#endif
#define TCPS_UNUSED(xParameter)         (Tcps_Void)(xParameter)

/* Copy a string into a fixed size buffer.  Zero the buffer to prevent
 * leaking any extra data out of the TEE.
 */
#define COPY_BUFFER_FROM_STRING(buff, str) \
    memset((buff).buffer, 0, sizeof((buff).buffer)); \
    strcpy_s((buff).buffer, sizeof((buff).buffer), (str));

#define COPY_BUFFER(dest, src, srcLen) \
    if ((srcLen) < sizeof((dest).buffer)) { \
        memset((dest).buffer + (srcLen), 0, sizeof((dest).buffer) - (srcLen)); \
    } \
    memcpy((dest).buffer, (src), (srcLen));
