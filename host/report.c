// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static OE_Result OE_GetLocallyAttestedReport(
    OE_Enclave* enclave,
    const void* reportData,
    uint32_t reportDataSize,
    const void* enclaveParams,
    uint32_t enclaveParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;

    // Currently only fixed size report data size supported.
    if (reportData == NULL || reportDataSize != OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // Enclave params play the role of SGX_TargetInfo.
    if (enclaveParams == NULL || enclaveParamsSize != sizeof(SGX_TargetInfo))
        OE_THROW(OE_INVALID_PARAMETER);

    // An SGX_Report will be filled into the report buffer.
    if (reportBufferSize == NULL)
        OE_THROW(OE_INVALID_PARAMETER);

    if (reportBuffer == NULL || *reportBufferSize < sizeof(SGX_Report))
        OE_THROW(OE_BUFFER_TOO_SMALL);

    /*
     * Use enclaveParams  are target info.
     */
    SGX_TargetInfo* sgxTargetInfo = (SGX_TargetInfo*)enclaveParams;

    /*
     * Get SGX_Report from enclave.
     */
    SGX_ReportData* sgxReportData = (SGX_ReportData*)reportData;

    SGX_Report* sgxReport = (SGX_Report*)reportBuffer;

    OE_GetSGXReportArgs sgxReportArgs;

    sgxReportArgs.targetInfo = sgxTargetInfo;
    sgxReportArgs.reportData = sgxReportData;
    sgxReportArgs.report = sgxReport;

    OE_TRY(
        OE_ECall(
            enclave, OE_FUNC_GET_SGX_REPORT, (uint64_t)&sgxReportArgs, NULL));

OE_CATCH:

    return result;
}

static OE_Result OE_GetRemotelyAttestedReport(
    OE_Enclave* enclave,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* enclaveParams,
    uint32_t enclaveParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;

    if (reportData == NULL || reportDataSize != OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    // Since supplied enclave params are not used, they must be null.
    if (reportData == NULL || reportDataSize != OE_REPORT_DATA_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    /*
     * Get target info from Quoting Enclave.
     */
    SGX_TargetInfo* sgxTargetInfo = calloc(1, sizeof(*sgxTargetInfo));

    if (sgxTargetInfo == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    OE_TRY(SGX_GetQETargetInfo(sgxTargetInfo));

    /*
     * Get SGX_Report from the enclave.
     */
    SGX_Report* sgxReport = calloc(1, sizeof(*sgxReport));

    if (sgxReport == NULL)
        OE_THROW(OE_OUT_OF_MEMORY);

    OE_GetSGXReportArgs sgxReportArgs;

    sgxReportArgs.targetInfo = sgxTargetInfo;
    sgxReportArgs.reportData = (SGX_ReportData*)reportData;
    sgxReportArgs.report = sgxReport;

    OE_TRY(
        OE_ECall(
            enclave, OE_FUNC_GET_SGX_REPORT, (uint64_t)&sgxReportArgs, NULL));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_TRY(SGX_GetQuote(sgxReport, reportBuffer, reportBufferSize));

OE_CATCH:

    if (sgxTargetInfo)
    {
        memset(sgxTargetInfo, 0, sizeof(*sgxTargetInfo));
        free(sgxTargetInfo);
    }

    if (sgxReport)
    {
        memset(sgxReport, 0, sizeof(*sgxReport));
        free(sgxReport);
    }

    return result;
}

OE_Result OE_GetReport(
    OE_Enclave* enclave,
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* enclaveParams,
    uint32_t enclaveParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    if (options & OE_REPORT_OPTIONS_LOCAL_ATTESTATION)
        return OE_GetLocallyAttestedReport(
            enclave,
            reportData,
            reportDataSize,
            enclaveParams,
            enclaveParamsSize,
            reportBuffer,
            reportBufferSize);

    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
        return OE_GetRemotelyAttestedReport(
            enclave,
            reportData,
            reportDataSize,
            enclaveParams,
            enclaveParamsSize,
            reportBuffer,
            reportBufferSize);

    return OE_INVALID_PARAMETER;
}