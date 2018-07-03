// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Simple Parser for JSON. Closely matches the JSON standard except for
 * allowing a superset of JSON strings and numbers. That is, strings that
 * contain invalid escape sequences will be parsed without errors.
 * It is up to the string and number parser callbacks to validate the parsed
 * string and number.
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
 *      Any sequence of characters consisting of alnums, +, - and .,
 *      starting with a digit is considered a number.
 *      The callback must parse the number token into the
 *      appropriate number representation and raise errors if it is not a
 *      valid number.
 *
 * When a null is parsed,
 *      'null' callback is invoked.
 *
 * When a boolean is parsed,
 *      'boolean' callback is invoked with 1 or 0.
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
