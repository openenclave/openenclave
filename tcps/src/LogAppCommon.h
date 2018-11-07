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
    oe_result_t* Results;
} TCPS_LOG_APP_EVENT_RESPONSE_DATA;

typedef struct {
    oe_result_t StatusCode;
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
oe_result_t
TcpsLogAppInit(
    const char* const sLogPrefix);

// TODO deprecate
oe_result_t
TcpsLogAppEventId(
    const int Id);

oe_result_t
TcpsLogAppEventResponse(
    const TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

oe_result_t
TcpsLogAppEventResponseFailed(
    const TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA* const Payload);

oe_result_t
TcpsLogAppEventAutoApproved(
    const TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA* const Payload);

oe_result_t
TcpsLogAppEventManualApproved(
    const TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA* const Payload);

oe_result_t
TcpsLogAppEventManualRejected(
    const TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA* const Payload);

oe_result_t
TcpsLogAppEventInitialized(void);

Tcps_Void
TcpsLogAppClose(void);

#pragma region Deserializers

oe_result_t
TcpsCborDecodeAppEvent(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_DATA* const Payload);

oe_result_t
TcpsCborDecodeAppEventResponse(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

void
TcpsCborFreeAppEventResponse(
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload);

oe_result_t
TcpsCborDecodeAppEventResponseFailed(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA* const Payload);

oe_result_t
TcpsCborDecodeAppEventAutoApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA* const Payload);

oe_result_t
TcpsCborDecodeAppEventManualApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA* const Payload);

oe_result_t
TcpsCborDecodeAppEventManualRejected(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA* const Payload);

#pragma endregion
#endif
