// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Parser for a subset of JSON.
 * Supported: Objects, arrays, strings, numbers.
 * Not Supported: null, true, false.
 *
 * When a string is parsed:
 *      'string' callback is invoked, passing the start position and
 *      the length of the string, omitting the quote character.
 *      The callback must make sense of the string, performing un-escaping,
 *      handling utf encoding etc as needed.
 *
 * When a number is parsed:
 *      'number' callback is invoked, passing the start position and
 *      the length of the set of characters that makeup the number.
 *      Any sequence of characters consisting of alnums, +, - and . following
 *      starting with a digit is considered a number.
 *      The callback must parse the number token into the appropriate number
 * representation
 *      and raise errors if it is not a valid number.
 *
 * When an object is parsed:
 *      'beginObject' callback is invoked upon encountering a {.
 *      'endObject' callback is invoked upon encountering the corresponding }.
 *
 * When a property is parsed:
 *      'propertyName' is invoked upon parsing the property name.
 *      The value of the property can be a string, an object or an array.
 *      The appropriate callback will be called for the property value.
 *      The comma character is optional between the properties.
 *
 * When an array is parsed:
 *      'beginArray' callback is invoked upon encountering a [.
 *      'end' array callback is invoked upon encountering the corresponding ].
 *      The value of an array element can be a string, an object or an array.
 *      The appropriate callback will be called for the array element.
 *      The comma character is optional between the array elements.
 */

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
