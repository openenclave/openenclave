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

typedef struct _Property
{
    const char* name;
    uint32_t type;
} Property;

typedef struct _Schema
{
    uint32_t numProperties;
    Property properties[17];
} Schema;

#define NUM_LEVELS (4)

static const Schema g_Schema[NUM_LEVELS] = {
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

typedef struct _CallbackData
{
    // The TCB info to be validated against the JSON
    const TCBInfo* tcbInfo;

    // Current level of object
    uint32_t level;

    // Maximum levels seen
    int32_t maxLevel;

    // Current property that is being parsed in each level.
    uint32_t currentPropertyIdx[4];

    // The set of properties read in each level.
    uint32_t propertiesSeen[4][20];
    uint32_t numPropertiesSeen[4];

    oe_result_t schemaValidationResult;

    const char* errorMessage;
} CallbackData;

static bool _IsExpectingType(CallbackData* data, uint32_t type)
{
    if (data->level >= 0 && data->level <= 3)
    {
        return g_Schema[data->level]
                   .properties[data->currentPropertyIdx[data->level]]
                   .type == type;
    }

    return false;
}

static oe_result_t _beginObject(void* vdata)
{
    CallbackData* data = (CallbackData*)vdata;
    int32_t curLevel = data->level;

    if (curLevel == -1)
    {
        // Processing root object
        data->level = 0;
        data->maxLevel = 0;
        return OE_OK;
    }
    else
    {
        // Apply schema checks.
        if (_IsExpectingType(data, OBJECT) ||
            _IsExpectingType(data, OBJECT_ARRAY))
        {
            ++data->level;
            if (data->level > data->maxLevel)
            {
                data->maxLevel = data->level;
            }

            data->numPropertiesSeen[data->level] = 0;
            return OE_OK;
        }

        data->schemaValidationResult = OE_FAILURE;
        return OE_FAILURE;
    }
}

static oe_result_t _endObject(void* vdata)
{
    CallbackData* data = (CallbackData*)vdata;
    // Check that all expected properties have been read.
    int level = data->level--;

    if (level < NUM_LEVELS &&
        data->numPropertiesSeen[level] == g_Schema[level].numProperties)
        return OE_OK;

    data->schemaValidationResult = OE_FAILURE;
    return OE_FAILURE;
}

static oe_result_t _beginArray(void* vdata)
{
    OE_UNUSED(vdata);
    return OE_OK;
}

static oe_result_t _endArray(void* vdata)
{
    OE_UNUSED(vdata);
    return OE_OK;
}

static bool _json_strcmp(
    const char* s1,
    uint32_t len1,
    const char* s2,
    uint32_t len2)
{
    // String in json stream are not zero terminated.
    // Hence the special comparison function.
    return (len1 == len2) && (oe_strncmp(s1, s2, len1) == 0);
}

static oe_result_t _propertyName(
    void* vdata,
    const uint8_t* name,
    uint32_t nameLength)
{
    CallbackData* data = (CallbackData*)vdata;

    // Check if it is a valid property in currently level.
    int32_t propertyIdx = -1;
    uint8_t duplicate = 0;
    const Schema* schema = NULL;

    if (data->level <= 3)
    {
        // First find a matching property.
        schema = &g_Schema[data->level];
        for (uint32_t i = 0; i < schema->numProperties; ++i)
        {
            if (_json_strcmp(
                    (const char*)name,
                    nameLength,
                    schema->properties[i].name,
                    oe_strlen(schema->properties[i].name)))
            {
                propertyIdx = i;
                break;
            }
        }

        // Avoid duplicates.
        if (propertyIdx != -1)
        {
            // Since match refers to strings from the static schema, pointer
            // comparison can be used for equality.
            for (uint32_t i = 0; i < data->numPropertiesSeen[data->level]; ++i)
            {
                if (data->propertiesSeen[data->level][i] == propertyIdx)
                {
                    duplicate = 1;
                    break;
                }
            }

            if (!duplicate)
            {
                data->currentPropertyIdx[data->level] = propertyIdx;
                OE_TRACE_INFO(
                    "TCB Reader: Seen property: %s\n",
                    schema->properties[propertyIdx].name);
                data->numPropertiesSeen[data->level]++;
                return OE_OK;
            }
        }
    }

    data->schemaValidationResult = OE_FAILURE;
    return OE_FAILURE;
}

static oe_result_t _number(
    void* data,
    const uint8_t* value,
    uint32_t valueLength)
{
    return _IsExpectingType(data, NUMBER) ? OE_OK : OE_FAILURE;
}

static oe_result_t _string(void* data, const uint8_t* str, uint32_t strLength)
{
    return _IsExpectingType(data, STRING) ? OE_OK : OE_FAILURE;
}

static void _handleError(void* vdata, const char* msg)
{
    CallbackData* data = (CallbackData*)vdata;
    data->errorMessage = msg;

    OE_TRACE_ERROR("JSON parse error : %s\n", msg);
}

oe_result_t OE_VerifyTCBInfo(
    const TCBInfo* info,
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize)
{
    oe_result_t result = OE_FAILURE;
    CallbackData data = {0};
    data.tcbInfo = info;

    // Not yet in root which is level 0.
    data.level = -1;

    // If any schema errors are detected, this
    // will be set to OE_FAILURE
    data.schemaValidationResult = OE_OK;

    OE_JsonParserCallbackInterface intf = {
        _beginObject,
        _endObject,
        _beginArray,
        _endArray,
        _number,
        _string,
        _propertyName,
        _handleError,
    };

    OE_CHECK(OE_ParseJson(tcbInfoJson, tcbInfoJsonSize, &data, &intf));

    // Check that all expected levels are there and
    // no schema validation errors were found.
    if (data.maxLevel + 1 == NUM_LEVELS && data.schemaValidationResult == OE_OK)
    {
        result = OE_OK;
    }

done:
    return result;
}
