/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdint.h>
#include <cbor.h>
#include "cborhelper.h"
#include "LogAppCommon.h"
#include "TcpsLogCodes.h"
#include "tcps_settings.h"

#pragma region Decode TCPS_LOG_APP_EVENT

oe_result_t
TcpsCborDecodeAppEvent(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    CborParser parser;
    CborValue it;
    CborValue array;
    CborError err = CborNoError;
    uint64_t eventId64;

    if (Buffer == NULL ||
        Payload == NULL)
    {
        return OE_FAILURE;
    }

    CLEANUP_DECODER_ERR(cbor_parser_init(Buffer, BufferSize, 0, &parser, &it));

    if (!cbor_value_is_array(&it))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_enter_container(&it, &array));

    // EventId

    if (!cbor_value_is_unsigned_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_uint64(&array, &eventId64));
    if (eventId64 > UINT32_MAX)
    {
        err = CborErrorUnknownType;
        goto Cleanup;
    }
    Payload->EventId = (TCPS_LOG_ID)eventId64;
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // Payload

    if (!cbor_value_is_byte_string(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
        &array,
        (const uint8_t**)&Payload->Payload,
        &Payload->PayloadSize,
        &array));

    // Validate end

    if (!cbor_value_at_end(&array))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_leave_container(&it, &array));

    if (!cbor_value_at_end(&it))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

Cleanup:
    return err == CborNoError ? OE_OK : OE_FAILURE;
}

#pragma endregion

#pragma region Decode TCPS_LOG_APP_EVENT_RESPONSE

void
TcpsCborFreeAppEventResponse(
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload)
{
    if (Payload != NULL)
    {
        if (Payload->Policies != NULL)
        {
            TCPSFREE((void*)Payload->Policies);
            Payload->Policies = NULL;
        }

        if (Payload->Values != NULL)
        {
            TCPSFREE((void*)Payload->Values);
            Payload->Values = NULL;
        }

        if (Payload->Results != NULL)
        {
            TCPSFREE(Payload->Results);
            Payload->Results = NULL;
        }
    }
}

oe_result_t
TcpsCborDecodeAppEventResponse(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    CborParser parser;
    CborValue it;
    CborValue array;
    CborError err = CborNoError;
    size_t size;

    if (Buffer == NULL ||
        Payload == NULL)
    {
        return OE_FAILURE;
    }

    Payload->Policies = NULL;
    Payload->Results = NULL;
    Payload->Values = NULL;

    CLEANUP_DECODER_ERR(cbor_parser_init(Buffer, BufferSize, 0, &parser, &it));

    if (!cbor_value_is_array(&it))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_enter_container(&it, &array));

    // ApprovedCount

    if (!cbor_value_is_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_int_checked(&array, &Payload->ApprovedCount));
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // WrittenCount

    if (!cbor_value_is_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_int_checked(&array, &Payload->WrittenCount));
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // ResultsCount

    if (!cbor_value_is_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_int_checked(&array, &Payload->ResultsCount));
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // Policies

    Payload->Policies = TCPSALLOC(sizeof(char*) * Payload->WrittenCount);
    if (Payload->Policies == NULL)
    {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    for (int i = 0; i < Payload->WrittenCount; i++)
    {
        if (!cbor_value_is_text_string(&array))
        {
            err = CborErrorIllegalType;
            goto Cleanup;
        }

        CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
            &array,
            (const uint8_t**)&Payload->Policies[i],
            &size,
            &array));
    }

    // Values

    Payload->Values = TCPSALLOC(sizeof(char*) * Payload->WrittenCount);
    if (Payload->Values == NULL)
    {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    for (int i = 0; i < Payload->WrittenCount; i++)
    {
        if (!cbor_value_is_text_string(&array))
        {
            err = CborErrorIllegalType;
            goto Cleanup;
        }

        CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
            &array,
            (const uint8_t**)&Payload->Values[i],
            &size,
            &array));
    }

    // Results

    Payload->Results = TCPSALLOC(sizeof(oe_result_t) * Payload->ResultsCount);
    if (Payload->Results == NULL)
    {
        err = CborErrorOutOfMemory;
        goto Cleanup;
    }

    for (int i = 0; i < Payload->ResultsCount; i++)
    {
        if (!cbor_value_is_integer(&array))
        {
            err = CborErrorIllegalType;
            goto Cleanup;
        }

        CLEANUP_DECODER_ERR(cbor_value_get_int_checked(
            &array,
            (int*)Payload->Results + i));
        CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));
    }

    // Validate end

    if (!cbor_value_at_end(&array))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_leave_container(&it, &array));

    if (!cbor_value_at_end(&it))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

Cleanup:
    if (err != CborNoError)
    {
        TcpsCborFreeAppEventResponse(Payload);
    }

    return err == CborNoError ? OE_OK : OE_FAILURE;
}

#pragma endregion

#pragma region Decode TCPS_LOG_APP_EVENT_RESPONSE_FAILED

oe_result_t
TcpsCborDecodeAppEventResponseFailed(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_RESPONSE_FAILED_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    CborParser parser;
    CborValue it;
    CborValue array;
    CborError err = CborNoError;

    if (Buffer == NULL ||
        Payload == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    CLEANUP_DECODER_ERR(cbor_parser_init(Buffer, BufferSize, 0, &parser, &it));

    if (!cbor_value_is_array(&it))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_enter_container(&it, &array));

    // StatusCode

    if (!cbor_value_is_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_int(&array, (int*)&Payload->StatusCode));
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // Validate end

    if (!cbor_value_at_end(&array))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_leave_container(&it, &array));

    if (!cbor_value_at_end(&it))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

Cleanup:
    return err == CborNoError ? OE_OK : OE_FAILURE;
}

#pragma endregion

#pragma region Decode TCPS_LOG_APP_EVENT_AUTO_APPROVED

oe_result_t
TcpsCborDecodeAppEventAutoApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    CborParser parser;
    CborValue it;
    CborValue array;
    CborError err = CborNoError;
    size_t size;

    if (Buffer == NULL ||
        Payload == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    CLEANUP_DECODER_ERR(cbor_parser_init(Buffer, BufferSize, 0, &parser, &it));

    if (!cbor_value_is_array(&it))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_enter_container(&it, &array));

    // Policy

    if (!cbor_value_is_text_string(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_text_string(
        &array,
        &Payload->Policy,
        &size,
        &array));

    // Value

    if (!cbor_value_is_text_string(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_text_string(
        &array,
        &Payload->Value,
        &size,
        &array));

    // Validate end

    if (!cbor_value_at_end(&array))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_leave_container(&it, &array));

    if (!cbor_value_at_end(&it))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

Cleanup:
    return err == CborNoError ? OE_OK : OE_FAILURE;
}

#pragma endregion

#pragma region Decode TCPS_LOG_APP_EVENT_MANUAL_APPROVED

oe_result_t
TcpsCborDecodeAppEventManualApproved(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_APPROVED_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    CborParser parser;
    CborValue it;
    CborValue array;
    CborError err = CborNoError;
    size_t size;

    if (Buffer == NULL ||
        Payload == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    CLEANUP_DECODER_ERR(cbor_parser_init(Buffer, BufferSize, 0, &parser, &it));

    if (!cbor_value_is_array(&it))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_enter_container(&it, &array));

    // Policy

    if (!cbor_value_is_text_string(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
        &array,
        (const uint8_t**)&Payload->Policy,
        &size,
        &array));

    // Value

    if (!cbor_value_is_text_string(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_ref_byte_string(
        &array,
        (const uint8_t**)&Payload->Value,
        &size,
        &array));

    // FingerprintSlotId

    if (!cbor_value_is_integer(&array))
    {
        err = CborErrorIllegalType;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_get_int_checked(&array, &Payload->FingerprintSlotId));
    CLEANUP_DECODER_ERR(cbor_value_advance_fixed(&array));

    // Validate end

    if (!cbor_value_at_end(&array))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

    CLEANUP_DECODER_ERR(cbor_value_leave_container(&it, &array));

    if (!cbor_value_at_end(&it))
    {
        err = CborErrorTooManyItems;
        goto Cleanup;
    }

Cleanup:
    return err == CborNoError ? OE_OK : OE_FAILURE;
}

#pragma endregion

#pragma region Decode TCPS_LOG_APP_EVENT_MANUAL_REJECTED

oe_result_t
TcpsCborDecodeAppEventManualRejected(
    const uint8_t* const Buffer,
    const size_t BufferSize,
    TCPS_LOG_APP_EVENT_MANUAL_REJECTED_DATA* const Payload)
/*++

Routine Description:

Parameters:

--*/
{
    return TcpsCborDecodeAppEventAutoApproved(
        Buffer,
        BufferSize,
        (TCPS_LOG_APP_EVENT_AUTO_APPROVED_DATA*)Payload);
}

#pragma endregion
