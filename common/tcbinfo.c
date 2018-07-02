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
#define NUM_TCB_LEVELS (3)
#define MAX_NUM_PROPERTIES (17)

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
    OE_ParsedTcbInfo* parsedTcbInfo;

    // Current level of object
    uint32_t level;

    // Maximum levels seen
    int32_t maxLevel;

    // Current property that is being parsed in each level.
    uint32_t currentPropertyIdx[4];

    // The set of properties read in each level.
    uint32_t propertiesSeen[NUM_LEVELS][MAX_NUM_PROPERTIES];
    uint32_t numPropertiesSeen[NUM_LEVELS];
    OE_Tcb currentTcb;

    oe_result_t schemaValidationResult;

    // Index of current TCB Level. o), 1, or 2.
    uint32_t tcbLevelIndex;

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

const char* _GetCurrentPropertyName(CallbackData* data)
{
    if (data->level >= 0 && data->level <= 3)
    {
        return g_Schema[data->level]
            .properties[data->currentPropertyIdx[data->level]]
            .name;
    }

    return "";
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
            if (oe_strcmp(_GetCurrentPropertyName(data), "tcbLevels") == 0)
            {
                // There can at at most 3 Levels of TCB.
                ++data->tcbLevelIndex;
                if (data->tcbLevelIndex >= NUM_TCB_LEVELS)
                    return OE_FAILURE;
            }

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

static void _AggregateTCBInfo(OE_Tcb* tcb, OE_Tcb* aggregatedTcb)
{
    // Aggregate only if the statuses match.
    if (tcb->status != aggregatedTcb->status)
        return;
    // Choose the maximum value for each property.
    for (uint32_t i = 0;
         i < sizeof(tcb->sgxTCBCompSvn) / sizeof(tcb->sgxTCBCompSvn[0]);
         ++i)
    {
        if (tcb->sgxTCBCompSvn[i] > aggregatedTcb->sgxTCBCompSvn[i])
            aggregatedTcb->sgxTCBCompSvn[i] = tcb->sgxTCBCompSvn[i];
    }
    if (tcb->pceSvn > aggregatedTcb->pceSvn)
        aggregatedTcb->pceSvn = tcb->pceSvn;
}

static oe_result_t _endObject(void* vdata)
{
    CallbackData* data = (CallbackData*)vdata;
    int level = data->level--;

    if (oe_strcmp(_GetCurrentPropertyName(data), "tcbLevels") == 0)
    {
        // Aggregate the TCB info.
        _AggregateTCBInfo(
            &data->currentTcb, &data->parsedTcbInfo->aggregatedUpToDateTcb);
        _AggregateTCBInfo(
            &data->currentTcb, &data->parsedTcbInfo->aggregatedOutOfDateTcb);
        _AggregateTCBInfo(
            &data->currentTcb, &data->parsedTcbInfo->aggregatedRevokedTcb);

        // Clear current TCB.
        oe_memset(&data->currentTcb, 0, sizeof(data->currentTcb));
    }

    // Check that all expected properties have been read.
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

static bool _JsonStrEqual(
    const char* s1,
    uint32_t len1,
    const char* s2,
    uint32_t len2)
{
    // Strings in json stream are not zero terminated.
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
        // First, find a matching property.
        schema = &g_Schema[data->level];
        for (uint32_t i = 0; i < schema->numProperties; ++i)
        {
            if (_JsonStrEqual(
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
                data->numPropertiesSeen[data->level]++;
                return OE_OK;
            }
        }
    }

    data->schemaValidationResult = OE_FAILURE;
    return OE_FAILURE;
}

static oe_result_t _number(
    void* vdata,
    const uint8_t* value,
    uint32_t valueLength)
{
    CallbackData* data = (CallbackData*)vdata;
    const char* propertyName = _GetCurrentPropertyName(data);
    OE_Tcb* tcb = &data->currentTcb;

    // Read decimal property value.
    uint64_t propertyValue = 0;
    for (uint32_t i = 0; i < valueLength; ++i)
    {
        propertyValue = (propertyValue * 10) + value[i] - '0';
    }

    if (_IsExpectingType(data, NUMBER))
    {
        if (data->level == 1)
        {
            if (oe_strcmp(propertyName, "version") == 0)
            {
                OE_TRACE_INFO("TCB: version = %ld\n", propertyValue);
                data->parsedTcbInfo->version = propertyValue;
                return OE_OK;
            }
        }
        else if (data->level == 3)
        {
            if (oe_strcmp(propertyName, "pcesvn") == 0)
            {
                OE_TRACE_INFO("TCB: pcesvn = %ld\n", propertyValue);
                tcb->pceSvn = propertyValue;
                return OE_OK;
            }
            else
            {
                OE_TRACE_INFO(
                    "TCB: sgxtcbcomp%dsvn = %ld\n",
                    data->currentPropertyIdx[data->level] + 1,
                    propertyValue);
                tcb->sgxTCBCompSvn[data->currentPropertyIdx[data->level]] =
                    propertyValue;
                return OE_OK;
            }
        }
    }

    OE_TRACE_INFO("Unhandled number property: %s\n", propertyName);
    return OE_FAILURE;
}

static oe_result_t _string(void* vdata, const uint8_t* str, uint32_t strLength)
{
    CallbackData* data = (CallbackData*)vdata;
    const char* propertyName = _GetCurrentPropertyName(data);
    OE_Tcb* tcb = 0;
    if (_IsExpectingType(data, STRING))
    {
        if (data->level == 0)
        {
            if (oe_strcmp(propertyName, "signature") == 0)
            {
                OE_TRACE_INFO("signature: length = %d\n", strLength);
                // OE_TRACE_INFO("TCB: signature = %*.*s\n", strLength,
                // strLength, str);
                data->parsedTcbInfo->signature = str;
                data->parsedTcbInfo->signatureSize = strLength;
                return OE_OK;
            }
        }
        if (data->level == 1)
        {
            if (oe_strcmp(propertyName, "issueDate") == 0)
            {
                OE_TRACE_INFO("issueDate: length = %d\n", strLength);
                // OE_TRACE_INFO("TCB: date = %*.*s\n", strLength, strLength,
                // str);
                data->parsedTcbInfo->issueDate = str;
                data->parsedTcbInfo->issueDateSize = strLength;
                return OE_OK;
            }
            if (oe_strcmp(propertyName, "fmspc") == 0)
            {
                OE_TRACE_INFO("fmspc: length = %d\n", strLength);
                // OE_TRACE_INFO("TCB: fmspc = %*.*s\n", strLength, strLength,
                // str);
                data->parsedTcbInfo->fmspc = str;
                data->parsedTcbInfo->fmspcSize = strLength;
                return OE_OK;
            }
        }
        if (data->level == 2)
        {
            if (oe_strcmp(propertyName, "status") == 0)
            {
                tcb = &data->currentTcb;

                if (_JsonStrEqual((const char*)str, strLength, "Revoked", 7))
                {
                    OE_TRACE_INFO("TCB: status = Revoked\n");
                    tcb->status = OE_TCB_STATUS_REVOKED;
                    return OE_OK;
                }
                if (_JsonStrEqual((const char*)str, strLength, "OutOfDate", 9))
                {
                    OE_TRACE_INFO("TCB: status = OutOfDate\n");
                    tcb->status = OE_TCB_STATUS_OUT_OF_DATE;
                    return OE_OK;
                }
                if (_JsonStrEqual((const char*)str, strLength, "UpToDate", 8))
                {
                    OE_TRACE_INFO("TCB: status = UpToDate\n");
                    tcb->status = OE_TCB_STATUS_UP_TO_DATE;
                    return OE_OK;
                }
            }
        }
    }
    OE_TRACE_INFO("Unhandled string property: %s\n", propertyName);
    return OE_FAILURE;
}

static void _handleError(void* vdata, const char* msg)
{
    CallbackData* data = (CallbackData*)vdata;
    data->errorMessage = msg;

    OE_TRACE_ERROR("JSON parse error : %s\n", msg);
}

oe_result_t OE_ParseTCBInfo(
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize,
    OE_ParsedTcbInfo* parsedInfo)
{
    oe_result_t result = OE_FAILURE;
    CallbackData data = {0};

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

    if (parsedInfo == NULL || tcbInfoJson == NULL || tcbInfoJsonSize == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_memset(parsedInfo, 0, sizeof(*parsedInfo));
    data.parsedTcbInfo = parsedInfo;
    data.tcbLevelIndex = -1;
    parsedInfo->aggregatedUpToDateTcb.status = OE_TCB_STATUS_UP_TO_DATE;
    parsedInfo->aggregatedOutOfDateTcb.status = OE_TCB_STATUS_OUT_OF_DATE;
    parsedInfo->aggregatedRevokedTcb.status = OE_TCB_STATUS_REVOKED;

    // Not yet in root which is level 0.
    data.level = -1;

    // If any schema errors are detected, this
    // will be set to OE_FAILURE
    data.schemaValidationResult = OE_OK;

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
