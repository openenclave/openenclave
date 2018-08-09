// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/report.c"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/utils.h>
#include "quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _oe_get_local_report(
    oe_enclave_t* enclave,
    const void* optParams,
    uint32_t optParamsSize,
    void* reportBuffer,
    uint32_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_report_args_t* arg = NULL;

    /*
     * Perform basic parameters validation here on the host side. Thorough
     * validation will be done in the enclave side.
     */

    // optParams, if specified, must be a sgx_target_info_t. When optParams is
    // NULL, optParamsSize must be zero.
    if (optParams != NULL && optParamsSize != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Request local report.
    arg->flags = 0;

    if (optParams != NULL)
        memcpy(arg->optParams, optParams, optParamsSize);

    arg->optParamsSize = optParamsSize;

    arg->reportBuffer = reportBuffer;
    arg->reportBufferSize = reportBufferSize ? *reportBufferSize : 0;

    OE_CHECK(oe_ecall(enclave, OE_ECALL_GET_REPORT, (uint64_t)arg, NULL));
    result = arg->result;

    if (reportBufferSize)
        *reportBufferSize = arg->reportBufferSize;

done:
    if (arg)
    {
        oe_secure_zero_fill(arg, sizeof(*arg));
        free(arg);
    }

    return result;
}

static oe_result_t _oe_get_remote_report(
    oe_enclave_t* enclave,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t* sgxTargetInfo = NULL;
    sgx_report_t* sgxReport = NULL;
    uint32_t sgxReportSize = sizeof(sgx_report_t);
    oe_report_t parsedReport;

    // For remote attestation, the Quoting Enclave's target info is used.
    // optParams must not be supplied.
    if (optParams != NULL || optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBuffer == NULL)
        *reportBufferSize = 0;

    /*
     * Get target info from Quoting Enclave.
     */
    sgxTargetInfo = calloc(1, sizeof(sgx_target_info_t));

    if (sgxTargetInfo == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(sgx_get_qetarget_info(sgxTargetInfo));

    /*
     * Get sgx_report_t from the enclave.
     */
    sgxReport = (sgx_report_t*)calloc(1, sizeof(sgx_report_t));

    if (sgxReport == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        _oe_get_local_report(
            enclave,
            sgxTargetInfo,
            sizeof(*sgxTargetInfo),
            sgxReport,
            &sgxReportSize));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(sgx_get_quote(sgxReport, reportBuffer, reportBufferSize));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (oe_parse_report(reportBuffer, *reportBufferSize, &parsedReport) !=
        OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (memcmp(
            parsedReport.enclaveReport,
            &sgxReport->body,
            sizeof(sgxReport->body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;

done:

    if (sgxTargetInfo)
    {
        oe_secure_zero_fill(sgxTargetInfo, sizeof(*sgxTargetInfo));
        free(sgxTargetInfo);
    }

    if (sgxReport)
    {
        oe_secure_zero_fill(sgxReport, sizeof(*sgxReport));
        free(sgxReport);
    }

    return result;
}

oe_result_t oe_get_report(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    if (flags & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
        return _oe_get_remote_report(
            enclave, optParams, optParamsSize, reportBuffer, reportBufferSize);

    // If no flags are specified, default to local report.
    return _oe_get_local_report(
        enclave, optParams, optParamsSize, reportBuffer, reportBufferSize);
}

oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    uint32_t reportSize,
    const oe_utc_date_time_t* minCrlTcbIssueDate,
    oe_report_t* parsedReport)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t arg = {0};

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize == 0 || reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    arg.report = (uint8_t*)report;
    arg.reportSize = reportSize;
    arg.minCrlTcbIssueDate = minCrlTcbIssueDate;
    arg.result = OE_FAILURE;

    // Call enclave to verify the report. Do not ask the enclave to return a
    // parsed report since the parsed report will then contain pointers to
    // enclave memory. Instead, pass NULL as the optional parsedReport out
    // parameter and parse the report below if requested.
    OE_CHECK(oe_ecall(enclave, OE_ECALL_VERIFY_REPORT, (uint64_t)&arg, NULL));
    OE_CHECK(arg.result);

    // Optionally return parsed report.
    if (parsedReport != NULL)
        OE_CHECK(oe_parse_report(report, reportSize, parsedReport));

    result = OE_OK;
done:

    return result;
}
