// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include <openenclave/types.h>
#include "../common/report.c"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(SGX_ReportData));

static oe_result_t _SGX_CreateReport(
    const void* reportData,
    uint32_t reportDataSize,
    const void* targetInfo,
    uint32_t targetInfoSize,
    SGX_Report* report)
{
    oe_result_t result = OE_UNEXPECTED;

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
        oe_memcpy(&ti, targetInfo, targetInfoSize);

    if (reportData != NULL)
        oe_memcpy(&rd, reportData, reportDataSize);

    oe_memset(&r, 0, sizeof(SGX_Report));

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(&ti), "c"(&rd), "d"(&r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    oe_memcpy(report, &r, sizeof(SGX_Report));

    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_sgx_report(
    const void* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    void* reportBuffer,
    uint32_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;

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
    // the user can create correctly sized buffer and call oe_get_report again.
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
    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_sgx_target_info(SGX_TargetInfo* targetInfo)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_qe_target_info_args_t* args =
        (oe_get_qe_target_info_args_t*)oe_host_calloc(1, sizeof(*args));
    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        oe_ocall(
            OE_FUNC_GET_QE_TARGET_INFO,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));

    result = args->result;
    if (result == OE_OK)
        *targetInfo = args->targetInfo;

    result = OE_OK;
done:
    if (args)
    {
        oe_secure_zero_fill(args, sizeof(*args));
        oe_host_free(args);
    }

    return result;
}

static oe_result_t _oe_get_quote(
    const SGX_Report* sgxReport,
    uint8_t* quote,
    uint32_t* quoteSize)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t argSize = sizeof(oe_get_qe_target_info_args_t);

    // If quote buffer is NULL, then ignore passed in quoteSize value.
    // This treats scenarios where quote == NULL and *quoteSize == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quoteSize = 0;

    // Allocate memory for args structure + quote buffer.
    argSize += *quoteSize;

    oe_get_quote_args_t* args = (oe_get_quote_args_t*)oe_host_calloc(1, argSize);
    args->sgxReport = *sgxReport;
    args->quoteSize = *quoteSize;

    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        oe_ocall(
            OE_FUNC_GET_QUOTE,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));
    result = args->result;

    if (result == OE_OK || result == OE_BUFFER_TOO_SMALL)
        *quoteSize = args->quoteSize;

    if (result == OE_OK)
        oe_memcpy(quote, args->quote, *quoteSize);

done:
    if (args)
    {
        oe_secure_zero_fill(args, argSize);
        oe_host_free(args);
    }

    return result;
}

oe_result_t _oe_get_remote_report(
    const uint8_t* reportData,
    uint32_t reportDataSize,
    const void* optParams,
    uint32_t optParamsSize,
    uint8_t* reportBuffer,
    uint32_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    SGX_TargetInfo sgxTargetInfo = {0};
    SGX_Report sgxReport = {0};
    uint32_t sgxReportSize = sizeof(sgxReport);
    oe_report_t parsedReport;

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
    OE_CHECK(_oe_get_sgx_target_info(&sgxTargetInfo));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_CHECK(
        _oe_get_sgx_report(
            reportData,
            reportDataSize,
            &sgxTargetInfo,
            sizeof(sgxTargetInfo),
            &sgxReport,
            &sgxReportSize));

    /*
     * OCall: Get the quote for the local report.
     */
    OE_CHECK(_oe_get_quote(&sgxReport, reportBuffer, reportBufferSize));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (oe_parse_report(reportBuffer, *reportBufferSize, &parsedReport) != OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (oe_memcmp(
            parsedReport.enclaveReport,
            &sgxReport.body,
            sizeof(sgxReport.body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:

    return result;
}

oe_result_t oe_get_report(
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
        return _oe_get_remote_report(
            reportData,
            reportDataSize,
            optParams,
            optParamsSize,
            reportBuffer,
            reportBufferSize);
    }

    // If no options are specified, default to locally attestable report.
    return _oe_get_sgx_report(
        reportData,
        reportDataSize,
        optParams,
        optParamsSize,
        reportBuffer,
        reportBufferSize);
}

static oe_result_t _SafeCopyGetReportArgs(
    uint64_t argIn,
    oe_get_report_args_t* safeArg,
    uint8_t* reportBuffer)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_report_args_t* unsafeArg = (oe_get_report_args_t*)argIn;

    if (!unsafeArg || !oe_is_outside_enclave(unsafeArg, sizeof(*unsafeArg)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy arg to prevent TOCTOU issues.
    // All input fields now lie in enclave memory.
    oe_secure_memcpy(safeArg, unsafeArg, sizeof(*safeArg));

    if (safeArg->reportBufferSize > OE_MAX_REPORT_SIZE)
        safeArg->reportBufferSize = OE_MAX_REPORT_SIZE;

    // Ensure that output buffer lies outside the enclave.
    if (safeArg->reportBuffer &&
        !oe_is_outside_enclave(safeArg->reportBuffer, safeArg->reportBufferSize))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Use output buffer within enclave.
    if (safeArg->reportBuffer)
        safeArg->reportBuffer = reportBuffer;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _SafeCopyGetReportArgsOuput(
    oe_get_report_args_t* safeArg,
    uint64_t argIn)
{
    oe_result_t result = OE_UNEXPECTED;

    oe_get_report_args_t* unsafeArg = (oe_get_report_args_t*)argIn;

    if (safeArg->result == OE_OK)
    {
        // Perform validation again. The reportBuffer field could have been
        // changed. Use volatile to ensure that the compiler doesn't optimize
        // away the copy.
        uint8_t* volatile hostReportBuffer = unsafeArg->reportBuffer;
        if (!oe_is_outside_enclave(hostReportBuffer, safeArg->reportBufferSize))
            OE_RAISE(OE_UNEXPECTED);

        oe_secure_memcpy(
            hostReportBuffer, safeArg->reportBuffer, safeArg->reportBufferSize);
    }

    unsafeArg->reportBufferSize = safeArg->reportBufferSize;
    unsafeArg->result = safeArg->result;
    result = OE_OK;

done:
    return result;
}

oe_result_t _HandleGetReport(uint64_t argIn)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_report_args_t arg;

    uint8_t reportBuffer[OE_MAX_REPORT_SIZE];

    // Validate and copy args to prevent TOCTOU issues.
    OE_CHECK(_SafeCopyGetReportArgs(argIn, &arg, reportBuffer));

    // Host is not allowed to pass report data. Otherwise, the host can use the
    // enclave to put whatever data it wants in a report. The data field is
    // intended to be used for digital signatures and is not allowed to be
    // tampered with by the host.

    arg.result = oe_get_report(
        arg.options,
        NULL,
        0,
        (arg.optParamsSize != 0) ? arg.optParams : NULL,
        arg.optParamsSize,
        arg.reportBuffer,
        &arg.reportBufferSize);

    // Copy outputs to host memory.
    OE_CHECK(_SafeCopyGetReportArgsOuput(&arg, argIn));
    result = OE_OK;

done:
    return result;
}
