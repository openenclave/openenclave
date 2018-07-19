// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Standards compliant parser for JSON.
 * The parser allocates no memory and performs no schema validation.
 *
 * The parser can be supplied with a set of callbacks in
 * a _OE_JsonParserCallbackInterface struct instance.
 * Additional a void pointer to some data can be passed in.
 * This data pointer will be supplied back to each callback function.
 *
 * For each JSON primitive entity (string, number, boolean, null),
 * the corresponding  callback method is invoked.
 *
 * For arrays and objects, a 'begin' callback and an 'end' callback
 * are invoked.
 *
 * The parser does not convert numbers to numeric types (int, float etc).
 * Instead it passes the pointer to the token and the length.
 * This allows clients to interpret the number appropriately without any
 * loss in precision.
 * Similarly for string values, the pointer to the string and its length
 * (excluding the quotes) is supplied to the callback.
 * The client needs to perform any un-escaping as needed.
 */

typedef struct _OE_JsonParserCallbackInterface
{
    oe_result_t (*beginObject)(void* data, const uint8_t* itr);
    oe_result_t (*endObject)(void* data, const uint8_t* itr);
    oe_result_t (*beginArray)(void* data, const uint8_t* itr);
    oe_result_t (*endArray)(void* data, const uint8_t* itr);

    oe_result_t (*null)(void* data);
    oe_result_t (*boolean)(void* data, uint8_t value);

    oe_result_t (
        *number)(void* data, const uint8_t* value, uint32_t valueLength);
    oe_result_t (*string)(void* data, const uint8_t* str, uint32_t strLength);
    oe_result_t (
        *propertyName)(void* obj, const uint8_t* name, uint32_t nameLength);

    void (*handleError)(void* obj, uint32_t charPos, const char* msg);
} OE_JsonParserCallbackInterface;

oe_result_t OE_ParseJson(
    const uint8_t* json,
    uint32_t jsonLength,

    void* callbackData,
    const OE_JsonParserCallbackInterface* interface);

OE_EXTERNC_END

#endif // _OE_JSON_H
