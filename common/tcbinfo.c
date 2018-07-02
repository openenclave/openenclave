// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include "tcbinfo.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/json.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

enum
{
    NUMBER = 1,
    STRING = 2,
    OBJECT = 3,
    OBJECT_ARRAY = 4
};

typedef struct _property
{
    const char* name;
    uint32_t type;
} property_t;

typedef struct _schema
{
    uint32_t num_properties;
    property_t properties[17];
} schema_t;

#define NUM_LEVELS (4)
#define NUM_TCB_LEVELS (3)
#define MAX_NUM_PROPERTIES (17)

static const schema_t _schema[NUM_LEVELS] = {
    {2, {{"tcbInfo", OBJECT}, {"signature", STRING}}},
    {4,
     {{"version", NUMBER},
      {"issueDate", STRING},
      {"fmspc", STRING},
      {"tcbLevels", OBJECT_ARRAY}}},
    {2, {{"tcb", OBJECT}, {"status", STRING}}},
    {17,
     {{"sgxtcbcomp01svn", NUMBER},
      {"sgxtcbcomp02svn", NUMBER},
      {"sgxtcbcomp03svn", NUMBER},
      {"sgxtcbcomp04svn", NUMBER},
      {"sgxtcbcomp05svn", NUMBER},
      {"sgxtcbcomp06svn", NUMBER},
      {"sgxtcbcomp07svn", NUMBER},
      {"sgxtcbcomp08svn", NUMBER},
      {"sgxtcbcomp09svn", NUMBER},
      {"sgxtcbcomp10svn", NUMBER},
      {"sgxtcbcomp11svn", NUMBER},
      {"sgxtcbcomp12svn", NUMBER},
      {"sgxtcbcomp13svn", NUMBER},
      {"sgxtcbcomp14svn", NUMBER},
      {"sgxtcbcomp15svn", NUMBER},
      {"sgxtcbcomp16svn", NUMBER},
      {"pcesvn", NUMBER}}}};

typedef struct _callback_data
{
    // The TCB info to be validated against the JSON
    oe_parsed_tcb_info_t* parsed_tcb_info;

    // Current level of object
    uint32_t level;

    // Maximum levels seen
    int32_t max_level;

    // Current property that is being parsed in each level.
    uint32_t current_property_idx[4];

    // The set of properties read in each level.
    uint32_t properties_seen[NUM_LEVELS][MAX_NUM_PROPERTIES];
    uint32_t numproperties_seen[NUM_LEVELS];
    oe_tcb_t current_tcb;

    oe_result_t schema_validation_result;

    // Index of current TCB Level. o), 1, or 2.
    uint32_t tcb_level_idx;

    const char* error_message;
} callback_data_t;

static bool _is_expecting_type(callback_data_t* data, uint32_t type)
{
    if (data->level >= 0 && data->level <= 3)
    {
        return _schema[data->level]
                   .properties[data->current_property_idx[data->level]]
                   .type == type;
    }

    return false;
}

const char* _get_current_property_name(callback_data_t* data)
{
    if (data->level >= 0 && data->level <= 3)
    {
        return _schema[data->level]
            .properties[data->current_property_idx[data->level]]
            .name;
    }

    return "";
}

static oe_result_t _begin_object(void* vdata)
{
    callback_data_t* data = (callback_data_t*)vdata;
    int32_t curLevel = data->level;

    if (curLevel == -1)
    {
        // Processing root object
        data->level = 0;
        data->max_level = 0;
        return OE_OK;
    }
    else
    {
        // Apply schema checks.
        if (_is_expecting_type(data, OBJECT) ||
            _is_expecting_type(data, OBJECT_ARRAY))
        {
            if (oe_strcmp(_get_current_property_name(data), "tcbLevels") == 0)
            {
                // There can at at most 3 Levels of TCB.
                ++data->tcb_level_idx;
                if (data->tcb_level_idx >= NUM_TCB_LEVELS)
                    return OE_FAILURE;
            }

            ++data->level;
            if (data->level > data->max_level)
            {
                data->max_level = data->level;
            }

            data->numproperties_seen[data->level] = 0;
            return OE_OK;
        }

        data->schema_validation_result = OE_FAILURE;
        return OE_FAILURE;
    }
}

static void _aggregate_tcb_info(oe_tcb_t* tcb, oe_tcb_t* aggregated_tcb)
{
    // Aggregate only if the statuses match.
    if (tcb->status != aggregated_tcb->status)
        return;
    // Choose the maximum value for each property.
    for (uint32_t i = 0;
         i < sizeof(tcb->sgx_tcb_comp_svn) / sizeof(tcb->sgx_tcb_comp_svn[0]);
         ++i)
    {
        if (tcb->sgx_tcb_comp_svn[i] > aggregated_tcb->sgx_tcb_comp_svn[i])
            aggregated_tcb->sgx_tcb_comp_svn[i] = tcb->sgx_tcb_comp_svn[i];
    }
    if (tcb->pce_svn > aggregated_tcb->pce_svn)
        aggregated_tcb->pce_svn = tcb->pce_svn;
}

static oe_result_t _end_object(void* vdata)
{
    callback_data_t* data = (callback_data_t*)vdata;
    int level = data->level--;

    if (oe_strcmp(_get_current_property_name(data), "tcbLevels") == 0)
    {
        // Aggregate the TCB info.
        _aggregate_tcb_info(
            &data->current_tcb,
            &data->parsed_tcb_info->aggregated_uptodate_tcb);
        _aggregate_tcb_info(
            &data->current_tcb,
            &data->parsed_tcb_info->aggregated_outofdate_tcb);
        _aggregate_tcb_info(
            &data->current_tcb, &data->parsed_tcb_info->aggregated_revoked_tcb);

        // Clear current TCB.
        oe_memset(&data->current_tcb, 0, sizeof(data->current_tcb));
    }

    // Check that all expected properties have been read.
    if (level < NUM_LEVELS &&
        data->numproperties_seen[level] == _schema[level].num_properties)
        return OE_OK;

    data->schema_validation_result = OE_FAILURE;
    return OE_FAILURE;
}

static bool _json_str_equal(
    const char* s1,
    uint32_t len1,
    const char* s2,
    uint32_t len2)
{
    // Strings in json stream are not zero terminated.
    // Hence the special comparison function.
    return (len1 == len2) && (oe_strncmp(s1, s2, len1) == 0);
}

static oe_result_t _property_name(
    void* vdata,
    const uint8_t* name,
    uint32_t name_length)
{
    callback_data_t* data = (callback_data_t*)vdata;

    // Check if it is a valid property in currently level.
    int32_t property_idx = -1;
    uint8_t duplicate = 0;
    const schema_t* schema = NULL;

    if (data->level <= 3)
    {
        // First, find a matching property.
        schema = &_schema[data->level];
        for (uint32_t i = 0; i < schema->num_properties; ++i)
        {
            if (_json_str_equal(
                    (const char*)name,
                    name_length,
                    schema->properties[i].name,
                    oe_strlen(schema->properties[i].name)))
            {
                property_idx = i;
                break;
            }
        }

        // Avoid duplicates.
        if (property_idx != -1)
        {
            // Since match refers to strings from the static schema, pointer
            // comparison can be used for equality.
            for (uint32_t i = 0; i < data->numproperties_seen[data->level]; ++i)
            {
                if (data->properties_seen[data->level][i] == property_idx)
                {
                    duplicate = 1;
                    break;
                }
            }

            if (!duplicate)
            {
                data->current_property_idx[data->level] = property_idx;
                data->numproperties_seen[data->level]++;
                return OE_OK;
            }
        }
    }

    data->schema_validation_result = OE_FAILURE;
    return OE_FAILURE;
}

static oe_result_t _number(
    void* vdata,
    const uint8_t* value,
    uint32_t value_length)
{
    callback_data_t* data = (callback_data_t*)vdata;
    const char* property_name = _get_current_property_name(data);
    oe_tcb_t* tcb = &data->current_tcb;

    // Read decimal property value.
    uint64_t property_value = 0;
    for (uint32_t i = 0; i < value_length; ++i)
    {
        property_value = (property_value * 10) + value[i] - '0';
    }

    if (_is_expecting_type(data, NUMBER))
    {
        if (data->level == 1)
        {
            if (oe_strcmp(property_name, "version") == 0)
            {
                OE_TRACE_INFO("TCB: version = %ld\n", property_value);
                data->parsed_tcb_info->version = property_value;
                return OE_OK;
            }
        }
        else if (data->level == 3)
        {
            if (oe_strcmp(property_name, "pcesvn") == 0)
            {
                OE_TRACE_INFO("TCB: pcesvn = %ld\n", property_value);
                tcb->pce_svn = property_value;
                return OE_OK;
            }
            else
            {
                OE_TRACE_INFO(
                    "TCB: sgxtcbcomp%dsvn = %ld\n",
                    data->current_property_idx[data->level] + 1,
                    property_value);
                tcb->sgx_tcb_comp_svn[data->current_property_idx[data->level]] =
                    property_value;
                return OE_OK;
            }
        }
    }

    OE_TRACE_INFO("Unhandled number property: %s\n", property_name);
    return OE_FAILURE;
}

static oe_result_t _string(void* vdata, const uint8_t* str, uint32_t str_length)
{
    callback_data_t* data = (callback_data_t*)vdata;
    const char* property_name = _get_current_property_name(data);
    oe_tcb_t* tcb = 0;
    if (_is_expecting_type(data, STRING))
    {
        if (data->level == 0)
        {
            if (oe_strcmp(property_name, "signature") == 0)
            {
                OE_TRACE_INFO("signature: length = %d\n", str_length);
                // OE_TRACE_INFO("TCB: signature = %*.*s\n", str_length,
                // str_length, str);
                data->parsed_tcb_info->signature = str;
                data->parsed_tcb_info->signature_size = str_length;
                return OE_OK;
            }
        }
        if (data->level == 1)
        {
            if (oe_strcmp(property_name, "issueDate") == 0)
            {
                OE_TRACE_INFO("issue_date: length = %d\n", str_length);
                // OE_TRACE_INFO("TCB: date = %*.*s\n", str_length, str_length,
                // str);
                data->parsed_tcb_info->issue_date = str;
                data->parsed_tcb_info->issue_date_size = str_length;
                return OE_OK;
            }
            if (oe_strcmp(property_name, "fmspc") == 0)
            {
                OE_TRACE_INFO("fmspc: length = %d\n", str_length);
                // OE_TRACE_INFO("TCB: fmspc = %*.*s\n", str_length, str_length,
                // str);
                data->parsed_tcb_info->fmspc = str;
                data->parsed_tcb_info->fmspc_size = str_length;
                return OE_OK;
            }
        }
        if (data->level == 2)
        {
            if (oe_strcmp(property_name, "status") == 0)
            {
                tcb = &data->current_tcb;

                if (_json_str_equal((const char*)str, str_length, "Revoked", 7))
                {
                    OE_TRACE_INFO("TCB: status = Revoked\n");
                    tcb->status = OE_TCB_STATUS_REVOKED;
                    return OE_OK;
                }
                if (_json_str_equal(
                        (const char*)str, str_length, "OutOfDate", 9))
                {
                    OE_TRACE_INFO("TCB: status = OutOfDate\n");
                    tcb->status = OE_TCB_STATUS_OUT_OF_DATE;
                    return OE_OK;
                }
                if (_json_str_equal(
                        (const char*)str, str_length, "UpToDate", 8))
                {
                    OE_TRACE_INFO("TCB: status = UpToDate\n");
                    tcb->status = OE_TCB_STATUS_UP_TO_DATE;
                    return OE_OK;
                }
            }
        }
    }
    OE_TRACE_INFO("Unhandled string property: %s\n", property_name);
    return OE_FAILURE;
}

static void _handle_error(void* vdata, const char* msg)
{
    callback_data_t* data = (callback_data_t*)vdata;
    data->error_message = msg;

    OE_TRACE_ERROR("JSON parse error : %s\n", msg);
}

oe_result_t oe_parse_tcb_info_json(
    const uint8_t* tcb_info_json,
    uint32_t tcb_info_json_size,
    oe_parsed_tcb_info_t* parsed_info)
{
    oe_result_t result = OE_FAILURE;
    callback_data_t data = {0};

    OE_JsonParserCallbackInterface intf = {
        _begin_object,
        _end_object,
        NULL, // No special validation required for arrays
        NULL,
        _number,
        _string,
        _property_name,
        _handle_error,
    };

    if (parsed_info == NULL || tcb_info_json == NULL || tcb_info_json_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_memset(parsed_info, 0, sizeof(*parsed_info));
    data.parsed_tcb_info = parsed_info;
    data.tcb_level_idx = -1;
    parsed_info->aggregated_uptodate_tcb.status = OE_TCB_STATUS_UP_TO_DATE;
    parsed_info->aggregated_outofdate_tcb.status = OE_TCB_STATUS_OUT_OF_DATE;
    parsed_info->aggregated_revoked_tcb.status = OE_TCB_STATUS_REVOKED;

    // Not yet in root which is level 0.
    data.level = -1;

    // If any schema errors are detected, this
    // will be set to OE_FAILURE
    data.schema_validation_result = OE_OK;

    OE_CHECK(OE_ParseJson(tcb_info_json, tcb_info_json_size, &data, &intf));

    // Check that all expected levels are there and
    // no schema validation errors were found.
    if (data.max_level + 1 == NUM_LEVELS &&
        data.schema_validation_result == OE_OK)
    {
        result = OE_OK;
    }

done:
    return result;
}
