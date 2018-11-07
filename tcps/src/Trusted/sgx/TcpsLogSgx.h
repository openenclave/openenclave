/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <time.h>
#include "TcpsLog.h"

/* Currently every TA uses TLS itself for logging, and hence TLS has to be a part of the TCPS-SDK.
 * In the future, the Foundation TA should do remote logging of local entries on behalf of other TAs
 * and we should remove the TLS dependency from the TCPS-SDK.
 */
#define ENABLE_REMOTE_LOGGING

#ifdef ENABLE_REMOTE_LOGGING
# include "TcpsTls.h"

typedef enum 
{
    TCPS_LOG_SGX_REMOTE_TYPE_NONE,
    TCPS_LOG_SGX_REMOTE_TYPE_LOGAGGREGATOR,
    TCPS_LOG_SGX_REMOTE_TYPE_BLOCKCHAIN
} TCPS_LOG_SGX_REMOTE_TYPE;
#endif

typedef struct {
#ifdef ENABLE_REMOTE_LOGGING
    TCPS_LOG_SGX_REMOTE_TYPE RemoteType;
#endif
    union {
        struct {
            const char* LaTrustedCa;
            VerifyCertCallback VerifyCert;
        } LA;
        struct {
            char From[20 * 2 + 2 + 1];
            char Contract[20 * 2 + 2 + 1];
        } BC;
    } RemoteData;
    char RemoteIpAddress[16];
    uint16_t RemotePort;
    char LogPathPrefix[255];
    __time64_t Time;
    PTCPS_LOG_TIME TimeFunc;
} TCPS_LOG_SGX_CONFIGURATION;

oe_result_t
TcpsLogEventSgxPeerId(
    void* Handle,
    const TCPS_LOG_ID EventId,
    const TCPS_IDENTITY_LOG IdentityLabel,
    const bool Flush
);

oe_result_t
TcpsLogEventSgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    const bool Flush
);

oe_result_t
TcpsLogEventSgxId(
    void* Handle,
    const TCPS_LOG_ID EventId,
    const bool Flush
);

oe_result_t
TcpsLogEventExistingSgx(
    void* Handle,
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_VALIDATION_STATE* const ValidationState
);

oe_result_t
TcpsLogInitSgx(
    const TCPS_SHA256_DIGEST Seed,
    struct _TCPS_TA_ID_INFO* const IDData,
    const TCPS_LOG_SGX_CONFIGURATION* const Configuration,
    const bool EnableRollbackProtection,
    void** Handle
);

void
TcpsLogCloseSgx(
    void* Handle
);

#ifdef ENABLE_REMOTE_LOGGING
oe_result_t
TcpsGetPeerIdentityLabel(
    TCPS_TLS_HANDLE TlsHandle,
    TCPS_IDENTITY_LOG IdentityLabel
);
#endif

void
TcpsLogTimeProvisionSgx(
    __time64_t UntrustedTime
);

__time64_t
TcpsLogTrustedTimeSgx(
    __time64_t* seconds
);

__time64_t
TcpsLogUntrustedTimeSgx(
    __time64_t* seconds
);
