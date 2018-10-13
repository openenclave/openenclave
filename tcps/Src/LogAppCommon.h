/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <tcps.h>

typedef enum {
    TCPS_LOG_APP_EVENT_RESPONSE,
    TCPS_LOG_APP_EVENT_RESPONSE_FAILED,
    TCPS_LOG_APP_EVENT_AUTO_APPROVED,
    TCPS_LOG_APP_EVENT_MANUAL_APPROVED,
    TCPS_LOG_APP_EVENT_MANUAL_REJECTED,
    TCPS_LOG_APP_EVENT_INITIALIZED
} TCPS_LOG_APP_EVENT_ID;

#pragma region Serialization/Deserialization Structures

typedef struct {
    TCPS_LOG_APP_EVENT_ID EventId;
    uint8_t* Payload;
    size_t PayloadSize;
} TCPS_LOG_APP_EVENT_DATA;

typedef struct {
    int ApprovedCount;
    int WrittenCount;
    int ResultsCount;
    const char** Policies;
    const char** Values;
    Tcps_StatusCode* Results;
} TCPS_LOG_APP_EVENT_RESPONSE_DATA;

typedef struct {
    Tcps_StatusCode StatusCode;
} TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA;

typedef struct {
    const char* Policy;
    const char* Value;
} TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA, TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA;

typedef struct {
    const char* Policy;
    const char* Value;
    int FingerprintSlotId;
    const char* FingerprintSlotLabel;
} TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA;

#pragma endregion

#if 0
Tcps_StatusCode
TcpsLogAppInit(
    const char* const sLogPrefix);

// TODO deprecate
Tcps_StatusCode
TcpsLogAppEventId(
    const int Id);

Tcps_StatusCode
TcpsLogAppEventResponse(
    const TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

Tcps_StatusCode
TcpsLogAppEventResponseFailed(
    const TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA* const Payload);

Tcps_StatusCode
TcpsLogAppEventAutoApproved(
    const TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA* const Payload);

Tcps_StatusCode
TcpsLogAppEventManualApproved(
    const TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA* const Payload);

Tcps_StatusCode
TcpsLogAppEventManualRejected(
    const TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA* const Payload);

Tcps_StatusCode
TcpsLogAppEventInitialized(void);

Tcps_Void
TcpsLogAppClose(void);

#pragma region Deserializers

Tcps_StatusCode
TcpsCborDecodeAppEvent(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_DATA* const Payload);

Tcps_StatusCode
TcpsCborDecodeAppEventResponse(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

void
TcpsCborFreeAppEventResponse(
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

Tcps_StatusCode
TcpsCborDecodeAppEventResponseFailed(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA* const Payload);

Tcps_StatusCode
TcpsCborDecodeAppEventAutoApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA* const Payload);

Tcps_StatusCode
TcpsCborDecodeAppEventManualApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA* const Payload);

Tcps_StatusCode
TcpsCborDecodeAppEventManualRejected(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA* const Payload);

#pragma endregion
#endif
