// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/keys.h>
#include <openenclave/bits/mac.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <openenclave/types.h>
#include "../common/report.c"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

/*static void OE_Memcpy_s(volatile void* pv1, const volatile void* pv2, uint32_t len)
{
    volatile uint8_t* p1 = (uint8_t*) pv1;
    volatile uint8_t* p2 = (uint8_t*) pv2;
   
    for(uint32_t i=0; i < len; ++i) {
        p1[i] = p2[i];
    }    
}*/

static void OE_Memset_s(volatile void* pv, int v, uint32_t len)
{
    volatile uint8_t* p = (volatile uint8_t*) pv;
    for(uint32_t i=0; i < len; ++i) {
        p[i] = 0;
    }
}

static int OE_Memcmp_s(const volatile void* pv1, const volatile void* pv2, uint32_t len)
{
    volatile uint8_t* p1 = (uint8_t*) pv1;
    volatile uint8_t* p2 = (uint8_t*) pv2;
    uint8_t r = 0;

    for(uint32_t i=0; i < len; ++i) {
        r |= p1[i] ^ p2[i];
    }

    return r;
}

static OE_Result _SGX_CreateReport(
    const void* reportData,
    uint32_t reportDataSize,
    const void* targetInfo,
    uint32_t targetInfoSize,
    SGX_Report* report)
{
    OE_Result result = OE_UNEXPECTED;

    // Allocate aligned objects as required by EREPORT instruction.
    SGX_TargetInfo ti OE_ALIGNED(512) = {0};
    SGX_ReportData rd OE_ALIGNED(128) = {0};
    SGX_Report r OE_ALIGNED(512) = {0};

    /*
     * Reject invalid parameters (reportData may be null).
     * If targetInfo is null, SGX returns the report for the enclave itself.
     */
    if (!report)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (targetInfoSize > sizeof(SGX_TargetInfo) ||
        reportDataSize > sizeof(SGX_ReportData))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (targetInfo != NULL)
        OE_Memcpy(&ti, targetInfo, targetInfoSize);

    if (reportData != NULL)
        OE_Memcpy(&rd, reportData, reportDataSize);

    OE_Memset(&r, 0, sizeof(SGX_Report));

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(&ti), "c"(&rd), "d"(&r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    OE_Memcpy(report, &r, sizeof(SGX_Report));

    result = OE_OK;

done:

    return result;
}

static OE_Result _OE_GetSGXReport(
    const void* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    void* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;

    if (reportDataSize > OE_REPORT_DATA_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // optParams may be null, in which case SGX returns the report for the
    // enclave itself.
    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // If supplied, it must be a valid SGX_TargetInfo.
    if (optParams != NULL && optParamsSize != sizeof(SGX_TargetInfo))
        OE_RAISE(OE_INVALID_PARAMETER);

    // An SGX_Report will be filled into the report buffer.
    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // When supplied buffer is small, report the expected buffer size so that
    // the user can create correctly sized buffer and call OE_GetReport again.
    if (reportBuffer == NULL || *reportBufferSize < sizeof(SGX_Report))
    {
        *reportBufferSize = sizeof(SGX_Report);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(
        _SGX_CreateReport(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer));

    *reportBufferSize = sizeof(SGX_Report);

done:

    return result;
}

static OE_Result _OE_GetSGXTargetInfo(SGX_TargetInfo* targetInfo)
{
    OE_Result result = OE_OK;
    OE_GetQETargetInfoArgs* args =
        (OE_GetQETargetInfoArgs*)OE_HostCalloc(1, sizeof(*args));
    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        OE_OCall(
            OE_FUNC_GET_QE_TARGET_INFO,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));

    result = args->result;
    if (result == OE_OK)
        *targetInfo = args->targetInfo;

done:
    if (args)
    {
        OE_Memset_s(args, 0, sizeof(*args));
        OE_HostFree(args);
    }

    return result;
}

static OE_Result _OE_GetQuote(
    const SGX_Report* sgxReport,
    uint8_t* quote,
    uint32_t* quoteSize)
{
    OE_Result result = OE_OK;
    uint32_t argSize = sizeof(OE_GetQETargetInfoArgs);

    // If quote buffer is NULL, then ignore passed in quoteSize value.
    // This treats scenarios where quote == NULL and *quoteSize == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quoteSize = 0;

    // Allocate memory for args structure + quote buffer.
    argSize += *quoteSize;

    OE_GetQuoteArgs* args = (OE_GetQuoteArgs*)OE_HostCalloc(1, argSize);
    args->sgxReport = *sgxReport;
    args->quoteSize = *quoteSize;

    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        OE_OCall(
            OE_FUNC_GET_QUOTE,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));
    result = args->result;

    if (result == OE_OK || result == OE_BUFFER_TOO_SMALL)
        *quoteSize = args->quoteSize;

    if (result == OE_OK)
        OE_Memcpy(quote, args->quote, *quoteSize);

done:
    if (args)
    {
        OE_Memset_s(args, 0, argSize);
        OE_HostFree(args);
    }

    return result;
}

OE_Result _OE_GetRemoteReport(
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    OE_Result result = OE_OK;
    SGX_TargetInfo sgxTargetInfo = {0};
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(sgxReport);
    OE_Report parsedReport;

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * OCall: Get target info from Quoting Enclave.
     * This involves a call to host. The target provided by targetinfo does not
     * need to be trusted because returning a report is not an operation that
     * requires privacy. The trust decision is one of integrity verification
     * on the part of the report recipient.
     */
    OE_CHECK(_OE_GetSGXTargetInfo(&sgxTargetInfo));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_CHECK(
        _OE_GetSGXReport(
            reportData,
            reportDataSize,
            &sgxTargetInfo,
            sizeof(sgxTargetInfo),
            &sgxReport,
            &sgxReportSize));

    /*
     * OCall: Get the quote for the local report.
     */
    OE_CHECK(_OE_GetQuote(&sgxReport, reportBuffer, reportBufferSize));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (OE_ParseReport(reportBuffer, *reportBufferSize, &parsedReport) != OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (OE_Memcmp(
            parsedReport.enclaveReport,
            &sgxReport.body,
            sizeof(sgxReport.body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

done:

    return result;
}

OE_Result OE_GetReport(
    uint32_t options,
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
    {
        return _OE_GetRemoteReport(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer,
            reportBufferSize);
    }

    // If no options are specified, default to locally attestable report.
    return _OE_GetSGXReport(
        reportData,
        reportDataSize,
        optParams,
        optParamsSize,
        reportBuffer,
        reportBufferSize);
}

static OE_Result _OE_GetReportKey(const SGX_Report* sgxReport, SGX_Key* sgxKey)
{
    OE_Result result = OE_OK;
    SGX_KeyRequest sgxKeyRequest = {0};

    sgxKeyRequest.key_name = SGX_KEYSELECT_REPORT;
    OE_Memcpy(sgxKeyRequest.key_id, sgxReport->keyid, sizeof(sgxReport->keyid));
    
    OE_CHECK( OE_GetKey(&sgxKeyRequest, sgxKey));

done:
    OE_Memset_s(&sgxKeyRequest, 0, sizeof(sgxKeyRequest));
    return result;    
}

OE_Result OE_VerifyReport(
    const uint8_t* report,
    uint32_t reportSize,
    OE_Report* parsedReport)
{
    OE_Result result = OE_OK;
    OE_Report pReport = {0};
    SGX_Key sgxKey = {0};    

    SGX_Report* sgxReport = NULL;
    OE_MAC mac = {0};    

    OE_CHECK(OE_ParseReport(report, reportSize, &pReport));

    if (pReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        OE_RAISE(OE_UNSUPPORTED);
    }
    else
    {
        sgxReport = (SGX_Report*)report;

        OE_CHECK( _OE_GetReportKey(sgxReport, &sgxKey) );

        OE_CHECK(
            OE_GetMAC(
                (uint8_t*) &sgxKey,
                sizeof(sgxKey),
                (uint8_t*)&sgxReport->body,
                sizeof(sgxReport->body),
                &mac));

        if (OE_Memcmp_s(sgxReport->mac, mac.bytes, sizeof(mac)) != 0)
            OE_RAISE(OE_FAILURE);
    }

    if (parsedReport != NULL)
        *parsedReport = pReport;

done:
    OE_Memset_s(&sgxKey, 0, sizeof(sgxKey));

    return result;
}


OE_Result _HandleGetReport(uint64_t argIn)
{
    OE_GetReportArgs* argFromHost = (OE_GetReportArgs*)argIn;
    OE_GetReportArgs arg;

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost)))
        return OE_INVALID_PARAMETER;

    // Copy arg to prevent TOCTOU issues.
    // All input fields now lie in enclave memory.
    arg = *argFromHost;

    argFromHost->result = OE_GetReport(
        arg.options,
        (arg.reportDataSize != 0) ? arg.reportData : NULL,
        arg.reportDataSize,
        (arg.optParamsSize != 0) ? arg.optParams : NULL,
        arg.optParamsSize,
        arg.reportBuffer,
        arg.reportBufferSize);

    return OE_OK;
}

OE_Result _HandleVerifyReport(uint64_t argIn)
{
    OE_Result result = OE_OK;
    OE_VerifyReportArgs* argFromHost = (OE_VerifyReportArgs*)argIn;
    OE_VerifyReportArgs arg;
    uint8_t report[OE_MAX_REPORT_SIZE];

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    arg = *argFromHost;

    if (!arg.report || !OE_IsOutsideEnclave(arg.report, arg.reportSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (arg.reportSize > OE_MAX_REPORT_SIZE) 
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!argFromHost || !OE_IsOutsideEnclave(argFromHost, sizeof(*argFromHost))) 
        OE_RAISE(OE_INVALID_PARAMETER);       


    // Copy report to prevent TOCTOU issues.
    OE_Memcpy(report, arg.report, arg.reportSize);

    argFromHost->result = OE_VerifyReport(report, arg.reportSize, NULL);

done:

    return result;
}
