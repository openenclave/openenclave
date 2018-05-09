// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include "../result.h"
#include "../types.h"

OE_EXTERNC_BEGIN

typedef struct _OE_JsonParserCallbackInterface
{
    OE_Result (*beginObject)(void* data);
    OE_Result (*endObject)(void* data);
    OE_Result (*beginArray)(void* data);
    OE_Result (*endArray)(void* data);

    OE_Result (*number)(void* data, const uint8_t* value, uint32_t valueLength);
    OE_Result (*string)(void* data, const uint8_t* str, uint32_t strLength);
    OE_Result (
        *propertyName)(void* obj, const uint8_t* name, uint32_t nameLength);

    void (*handleError)(void* obj, const char* msg);
} OE_JsonParserCallbackInterface;

OE_Result OE_ParseJson(
    const uint8_t* json,
    uint32_t jsonLength,

    void* callbackData,
    const OE_JsonParserCallbackInterface* interface);

OE_EXTERNC_END

#endif // _OE_JSON_H
