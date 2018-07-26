// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JSON_H
#define _OE_JSON_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Parser for JSON that supports all standard JSON syntax as
 * described at www.json.org.
 *
 * The parser allocates no memory and performs no schema validation.
 *
 * The parser can be supplied with a set of callbacks in
 * a oe_json_parser_callback_interface struct instance.
 * Additional a void pointer to some data can be passed in.
 * This data pointer will be supplied back to each callback function.
 *
 * For each JSON primitive entity (string, number, boolean, null),
 * the corresponding callback method is invoked.
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

typedef struct _oe_json_parser_callback_interface
{
    oe_result_t (*begin_object)(void* data);
    oe_result_t (*end_object)(void* data);
    oe_result_t (*begin_array)(void* data);
    oe_result_t (*end_array)(void* data);

    oe_result_t (*null)(void* data);
    oe_result_t (*boolean)(void* data, uint8_t value);

    oe_result_t (
        *number)(void* data, const uint8_t* value, uint32_t valueLength);
    oe_result_t (*string)(void* data, const uint8_t* str, uint32_t strLength);
    oe_result_t (
        *property_name)(void* obj, const uint8_t* name, uint32_t nameLength);

    void (*handle_error)(void* obj, uint32_t charPos, const char* msg);
} oe_json_parser_callback_interface;

oe_result_t oe_parse_json(
    const uint8_t* json,
    uint32_t json_length,
    void* callback_data,
    const oe_json_parser_callback_interface* interface);

OE_EXTERNC_END

#endif // _OE_JSON_H
