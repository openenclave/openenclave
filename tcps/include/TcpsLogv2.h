/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
/* Licensed under the MIT License. */
#pragma once

#include <time.h>
#include "tcps.h"
#include "TcpsLogCodes.h"
#include "ICryptUtil.h"
#include <openenclave/bits/timetypes.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct TCPS_LOG_ATTRIBUTES TCPS_LOG_ATTRIBUTES;

#pragma region TcpsLogOpen

    typedef __time64_t (*PTCPS_LOG_TIME)(
        __time64_t *const seconds);

    oe_result_t
    TcpsLogOpen(
        _Outptr_ TCPS_LOG_ATTRIBUTES **LogAttributes,
        _In_ const TCPS_IDENTITY_PRIVATE *SigningIdentity,
        _In_ const TCPS_IDENTITY_PUBLIC *ValidationIdentity,
        _In_ PTCPS_LOG_TIME GetTimeHandler);

#pragma endregion TcpsLogOpen

#pragma region TcpsLogAddCategory

    typedef oe_result_t (*PTCPS_LOG_CATEGORY_PERSIST)(
        void *Context,
        const char *Label,
        const uint8_t *EncodedCategory,
        size_t EncodedCategorySize);

    typedef oe_result_t (*PTCPS_LOG_CATEGORY_RECOVER)(
        void *Context,
        const char *Label,
        uint8_t **EncodedCategory,
        size_t *EncodedCategorySize);

    typedef oe_result_t (*PTCPS_LOG_COUNTER_CREATE)(
        void *Context,
        uint8_t **CounterId,
        size_t *CounterIdSize,
        uint8_t **CounterValue,
        size_t *CounterValueSize);

    typedef oe_result_t (*PTCPS_LOG_COUNTER_VALIDATE)(
        void *Context,
        const uint8_t *CounterId,
        size_t CounterIdSize,
        const uint8_t *CounterValue,
        size_t CounterValueSize);

    typedef oe_result_t (*PTCPS_LOG_COUNTER_INCREMENTGET)(
        void *Context,
        const uint8_t *CounterId,
        size_t CounterIdSize,
        uint8_t **CounterValue,
        size_t *CounterValueSize);

    oe_result_t
    TcpsLogAddCategory(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes,
        _In_ const char *Label,
        _In_ const TCPS_SHA256_DIGEST Seed,
        _In_ PTCPS_LOG_CATEGORY_PERSIST PersistCategoryHandler,
        _In_ PTCPS_LOG_CATEGORY_RECOVER RecoverCategoryHandler,
        _In_ PTCPS_LOG_COUNTER_CREATE CreateCounterHandler,
        _In_ PTCPS_LOG_COUNTER_VALIDATE ValidateCounterHandler,
        _In_ PTCPS_LOG_COUNTER_INCREMENTGET IncrementGetCounterHandler,
        _In_ void *HandlerContext);

#pragma endregion TcpsLogAddCategory

#pragma region TcpsLogSetLocalTransport

    typedef oe_result_t (*PTCPS_LOG_LOCAL_WRITE)(
        void *Context,
        const char *CategoryLabel,
        const uint8_t *EncodedEvent,
        size_t EncodedEventSize);

    typedef oe_result_t (*PTCPS_LOG_LOCAL_READ)(
        void *Context,
        const char *CategoryLabel,
        uint8_t **EncodedEvent,
        size_t *EncodedEventSize);

    typedef oe_result_t (*PTCPS_LOG_LOCAL_CLEAR)(
        void *Context,
        const char *CategoryLabel);

    oe_result_t
    TcpsLogSetLocalTransport(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes,
        _In_ PTCPS_LOG_LOCAL_WRITE WriteLocalEventHandler,
        _In_ PTCPS_LOG_LOCAL_READ ReadLocalBlockHandler,
        _In_ PTCPS_LOG_LOCAL_CLEAR ClearLocalBlockHandler,
        _In_ void *HandlerContext);

#pragma endregion TcpsLogSetLocalTransport

#pragma region TcpsLogSetRemoteTransport

    typedef oe_result_t (*PTCPS_LOG_REMOTE_WRITE)(
        void *Context,
        const char *CategoryLabel,
        const uint8_t *EncodedBlock,
        size_t EncodedBlockSize);

    oe_result_t
    TcpsLogSetRemoteTransport(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes,
        _In_ PTCPS_LOG_REMOTE_WRITE WriteRemoteBlockHandler,
        _In_ void *HandlerContext);

#pragma endregion TcpsLogSetRemoteTransport

#pragma region TcpsLogWrite

    oe_result_t
    TcpsLogWrite(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes,
        _In_ const char *CategoryLabel,
        _In_ const uint8_t *Payload,
        _In_ size_t PayloadSize);

#pragma endregion TcpsLogWrite

#pragma region TcpsLogFlush

    oe_result_t
    TcpsLogFlush(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes,
        _In_ const char *CategoryLabel);

#pragma endregion TcpsLogFlush

#pragma region TcpsLogClose

    oe_result_t
    TcpsLogClose(
        _Inout_ TCPS_LOG_ATTRIBUTES *LogAttributes);

#pragma endregion TcpsLogClose

#ifdef __cplusplus
}
#endif
