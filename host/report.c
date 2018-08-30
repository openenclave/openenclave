// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/utils.h>
#include "../common/quote.h"
#include "quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _oe_get_local_report(
    oe_enclave_t* enclave,
    const void* optParams,
    size_t optParamsSize,
    void* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_report_args_t* arg = NULL;

    // optParams, if specified, must be a sgx_target_info_t. When optParams is
    // NULL, optParamsSize must be zero.
    if (optParams != NULL && optParamsSize != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportBuffer == NULL || *reportBufferSize < sizeof(sgx_report_t))
    {
        *reportBufferSize = sizeof(sgx_report_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (optParams != NULL)
        memcpy(arg->optParams, optParams, optParamsSize);

    arg->optParamsSize = optParamsSize;

    OE_CHECK(oe_ecall(enclave, OE_ECALL_GET_SGX_REPORT, (uint64_t)arg, NULL));

    memcpy(reportBuffer, &arg->sgxReport, sizeof(sgx_report_t));
    *reportBufferSize = sizeof(sgx_report_t);
    result = OE_OK;

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
    size_t optParamsSize,
    uint8_t* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t* sgxTargetInfo = NULL;
    sgx_report_t* sgxReport = NULL;
    size_t sgxReportSize = sizeof(sgx_report_t);

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
            (uint8_t*)sgxReport,
            &sgxReportSize));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(sgx_get_quote(sgxReport, reportBuffer, reportBufferSize));

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
    size_t optParamsSize,
    uint8_t* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* header = (oe_report_header_t*)reportBuffer;

    // Reserve space in the buffer for header.
    if (reportBuffer && reportBufferSize)
    {
        if (*reportBufferSize >= sizeof(oe_report_header_t))
        {
            OE_CHECK(
                oe_safe_add_u64(
                    (uint64_t)reportBuffer,
                    sizeof(oe_report_header_t),
                    (uint64_t*)&reportBuffer));
            *reportBufferSize -= sizeof(oe_report_header_t);
        }
    }

    if (flags & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
    {
        OE_CHECK(
            _oe_get_remote_report(
                enclave,
                optParams,
                optParamsSize,
                reportBuffer,
                reportBufferSize));
    }
    else
    {
        // If no flags are specified, default to locally attestable report.
        OE_CHECK(
            _oe_get_local_report(
                enclave,
                optParams,
                optParamsSize,
                reportBuffer,
                reportBufferSize));
    }

    header->version = OE_REPORT_HEADER_VERSION;
    header->report_type = (flags & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
                              ? OE_REPORT_TYPE_SGX_REMOTE
                              : OE_REPORT_TYPE_SGX_LOCAL;
    header->report_size = *reportBufferSize;
    OE_CHECK(
        oe_safe_add_u64(
            *reportBufferSize, sizeof(oe_report_header_t), reportBufferSize));
    result = OE_OK;

done:
    if (result == OE_BUFFER_TOO_SMALL)
    {
        *reportBufferSize += sizeof(oe_report_header_t);
    }

    return result;
}

oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t reportSize,
    oe_report_t* parsedReport)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oeReport = {0};
    oe_verify_report_args_t arg = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reportSize == 0 || reportSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, reportSize, &oeReport));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        // Quote attestation can be done entirely on the host side.
        OE_CHECK(
            VerifyQuoteImpl(
                header->report,
                header->report_size,
                NULL,
                0,
                NULL,
                0,
                NULL,
                0));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        if (enclave == NULL)
            OE_RAISE(OE_INVALID_PARAMETER);

        // Local report attestation can only be done on the enclave side.
        arg.report = (uint8_t*)report;
        arg.reportSize = reportSize;
        arg.result = OE_FAILURE;

        // Call enclave to verify the report. Do not ask the enclave to return a
        // parsed report since the parsed report will then contain pointers to
        // enclave memory. Instead, pass NULL as the optional parsedReport out
        // parameter and parse the report below if requested.
        OE_CHECK(
            oe_ecall(enclave, OE_ECALL_VERIFY_REPORT, (uint64_t)&arg, NULL));
        OE_CHECK(arg.result);
    }

    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Optionally return parsed report.
    if (parsedReport != NULL)
        OE_CHECK(oe_parse_report(report, reportSize, parsedReport));

    result = OE_OK;
done:
    return result;
}
