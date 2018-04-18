// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/report.c"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include "quote.h"

OE_Result OE_GetReport(
    OE_Enclave* enclave,
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;
    OE_GetReportArgs* arg = NULL;

    /*
     * Perform basic parameters validation here on the host side. Thorough
     * validation will be done in the enclave side.
     */

    // reportData can either be NULL or it can be a stream of bytes with length
    // < OE_REPORT_DATA_SIZE. When reportData is NULL, the reportSize must be
    // zero.
    if (reportData == NULL && reportDataSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // optParams, if specified, must be a SGX_TargetInfo. When optParams is
    // NULL, optParamsSize must be zero.
    if (optParams != NULL && optParamsSize != sizeof(SGX_TargetInfo))
        OE_THROW(OE_INVALID_PARAMETER);

    if (optParams == NULL && optParamsSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    if (reportData != NULL)
        memcpy(arg->reportData, reportData, reportDataSize);

    arg->options = options;

    arg->reportDataSize = reportDataSize;

    if (optParams != NULL)
        memcpy(arg->optParams, reportData, reportDataSize);

    arg->optParamsSize = optParamsSize;

    arg->reportBuffer = reportBuffer;
    arg->reportBufferSize = reportBufferSize;

    OE_TRY(OE_ECall(enclave, OE_FUNC_GET_REPORT, (uint64_t)arg, NULL));
    result = arg->result;

OE_CATCH:
    if (arg)
    {
        memset(arg, 0, sizeof(*arg));
        free(arg);
    }

    return result;
}
