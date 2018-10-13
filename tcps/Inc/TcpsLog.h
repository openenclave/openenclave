/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <time.h>
#include "tcps.h"
#include "TcpsLogCodes.h"
#include "ICryptUtil.h"
#include "tcps_time.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCPS_IDENTITY_LOG_SIZE (sizeof(TCPS_SHA256_DIGEST) * 2 + 1)

typedef uint8_t TCPS_SHA256_DIGEST[SHA256_DIGEST_LENGTH];
typedef char TCPS_IDENTITY_LOG[TCPS_IDENTITY_LOG_SIZE];

typedef enum _TCPS_LOG_VALIDATION_STATE
{
    TCPS_LOG_VALIDATION_STATE_OK,
    TCPS_LOG_VALIDATION_STATE_BREAK,
    TCPS_LOG_VALIDATION_STATE_BAD
} TCPS_LOG_VALIDATION_STATE;

typedef struct _TCPS_LOG_EVENT {
    size_t PayloadSize;
    const uint8_t* Payload;
    __time64_t Timestamp;
    const uint8_t* LogChainDigest; // TCPS_SHA256_DIGEST
} TCPS_LOG_EVENT;

//
// Generic callbacks
//

// local/remote logging, any writing
typedef Tcps_StatusCode (*PTCPS_LOG_WRITE)(
    void* CallbackHandle,
    const uint8_t* const Buffer, 
    const size_t BufferSize,
    const TCPS_IDENTITY_LOG Identity
);

// reading of local log, any reading
typedef Tcps_StatusCode (*PTCPS_LOG_READ)(
    void* CallbackHandle,
    uint8_t** const Buffer, 
    size_t* const BufferSize, 
    const TCPS_IDENTITY_LOG Identity
);

typedef Tcps_StatusCode (*PTCPS_LOG_IDENTITY)(
    void* CallbackHandle,
    const TCPS_IDENTITY_LOG Identity
);

typedef Tcps_StatusCode (*PTCPS_LOG_VALIDATE)(
    const TCPS_LOG_EVENT* const Entry,
    const bool LogChainBroken,
    const TCPS_IDENTITY_PUBLIC* const SignedIdentities,
    const size_t SignedIdentitiesCount
);

// time
typedef __time64_t(*PTCPS_LOG_TIME)(
    __time64_t* const seconds
);

//
// Signature specific callbacks
//

typedef Tcps_StatusCode (*PTCPS_LOG_COUNTER_VALIDATE)(
    void* CallbackHandle,
    const uint8_t* const CounterIdBuffer,
    const size_t CounterIdBufferSize,
    const uint8_t* const CounterValueBuffer,
    const size_t CounterValueBufferSize
);

typedef Tcps_StatusCode (*PTCPS_LOG_COUNTER_CREATE)(
    void* CallbackHandle,
    uint8_t** const CounterIdBuffer,
    size_t* const CounterIdBufferSize,
    uint8_t** const CounterValueBuffer,
    size_t* const CounterValueBufferSize
);

typedef Tcps_StatusCode (*PTCPS_LOG_COUNTER_INCREMENTGET)(
    void* CallbackHandle,
    const uint8_t* const CounterIdBuffer,
    const size_t CounterIdBufferSize,
    uint8_t** const CounterValueBuffer,
    size_t* CounterValueBufferSize
);

/*++

Routine Description:

    Initializes logging infrastructure

Parameters:

    SignIdentity - Private key of the log owner

    ValidateIdentity - Public key of the log owner

    PemCertificateChain - Device certificate chain

    LocalLogCallback - Callback for local log storage; optional, at least one of Local/Remote should be specified

    SignLocal - Sign local logs as they would be stored outside of TEE

    LocalLogPullCallback - Callback to retrieve local logs for validation/upload; only needed if LocalLogHandler is specified

    LocalLogClearCallback - Callback to clear local logs; only needed if local log handler is specified

    RemoteLogCallback - Callback for remote log storage; optional, at least one of Local/Remote should be specified

    RemoteLogFlushCallback - Callback to flush remote logs; only needed if RemoteLogHandler is specified

    TimeCallback - 

    Seed - Initial log digest

    CallbackContext - Passthrough context for callbacks

    Handle - Handle for logging; needs to be released with TcpsLogClose

--*/
Tcps_StatusCode
TcpsLogInit(
    const TCPS_IDENTITY_PRIVATE* const SignIdentity,
    const TCPS_IDENTITY_PUBLIC* const ValidateIdentity,
    const PTCPS_LOG_WRITE LocalLogCallback,
    const bool SignLocal,
    const PTCPS_LOG_READ LocalLogPullCallback,
    const PTCPS_LOG_IDENTITY LocalLogClearCallback,
    const PTCPS_LOG_WRITE RemoteLogCallback,
    const PTCPS_LOG_IDENTITY RemoteLogFlushCallback,
    const PTCPS_LOG_READ CounterRecoverCallback,
    const PTCPS_LOG_WRITE CounterWriteCallback,
    const PTCPS_LOG_COUNTER_VALIDATE CounterValidateCallback,
    const PTCPS_LOG_COUNTER_CREATE CounterCreateCallback,
    const PTCPS_LOG_COUNTER_INCREMENTGET CounterIncrementGetCallback,
    const PTCPS_LOG_TIME TimeCallback,
    const TCPS_SHA256_DIGEST Seed,
    void* CallbackContext,
    void** Handle
);

/*++

Routine Description:

    Released logging handle

Parameters:

    Handle - Handle obtained from TcpsLogInit

--*/
void
TcpsLogClose(
    void* Handle
);

/*++

Routine Description:

    Logs an event

Parameters:

    Handle - Handle obtained from TcpsLogInit

    Payload - Buffer with the data to be logged

    PayloadSize - Size of the buffer to be logged

    Flush - Block until the event is logged all the way to the last link in the chain

--*/
Tcps_StatusCode
TcpsLogEvent(
    void* Handle,
    const uint8_t* const Payload,
    const size_t PayloadSize,
    const bool Flush
);

/*++

Routine Description:

    Resign and relog

Parameters:

    Handle - Handle obtained from TcpsLogInit

    Buffer - Data buffer with a signed log entry

    BufferSize - Size of Buffer

    ValidationState - State of log validation

--*/
Tcps_StatusCode
TcpsLogEventExisting(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_VALIDATION_STATE* const ValidationState
);

/*++

Routine Description:

    Parse a block of log entries

Parameters:

    Buffer - Data buffer with possibly multiple log entries

    BufferSize - Size of Buffer

    SeedDigest - Initial log digest

    FinalDigest - Last item digest, optional

    LogChainBreakDetected - Detected a break in log chain

    ValidateCallback - Optional, called per log entry

    LastEntryDigest - 

--*/
Tcps_StatusCode
TcpsLogValidate(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const TCPS_SHA256_DIGEST SeedDigest,
    const TCPS_SHA256_DIGEST FinalDigest,
    bool* const LogChainBreakDetected,
    const PTCPS_LOG_VALIDATE ValidateCallback,
    TCPS_SHA256_DIGEST LastEntryDigest
);

Tcps_StatusCode
TcpsLogRemoteFlushCreate(
    const TCPS_IDENTITY_LOG Identity,
    uint8_t** const Buffer,
    size_t* const BufferSize
);

#ifdef __cplusplus
}
#endif
