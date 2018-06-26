// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_JsonParserCallbackInterface
{
    oe_result_t (*beginObject)(void* data);
    oe_result_t (*endObject)(void* data);
    oe_result_t (*beginArray)(void* data);
    oe_result_t (*endArray)(void* data);

    oe_result_t (
        *number)(void* data, const uint8_t* value, uint32_t valueLength);
    oe_result_t (*string)(void* data, const uint8_t* str, uint32_t strLength);
    oe_result_t (
        *propertyName)(void* obj, const uint8_t* name, uint32_t nameLength);

    void (*handleError)(void* obj, const char* msg);
} OE_JsonParserCallbackInterface;

oe_result_t OE_ParseJson(
    const uint8_t* json,
    uint32_t jsonLength,

    void* callbackData,
    const OE_JsonParserCallbackInterface* interface);

OE_EXTERNC_END

#endif // _OE_JSON_H
