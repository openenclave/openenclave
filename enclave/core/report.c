// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

OE_STATIC_ASSERT(sizeof(oe_identity_t) == 96);

OE_STATIC_ASSERT(sizeof(oe_report_t) == 144);

oe_result_t sgx_create_report(
    const void* report_data,
    size_t report_data_size,
    const void* targetInfo,
    size_t targetInfoSize,
    sgx_report_t* report)
{
    oe_result_t result = OE_UNEXPECTED;

    // Allocate aligned objects as required by EREPORT instruction.
    sgx_target_info_t ti OE_ALIGNED(512) = {{0}};
    sgx_report_data_t rd OE_ALIGNED(128) = {{0}};
    sgx_report_t r OE_ALIGNED(512) = {{{0}}};

    /*
     * Reject invalid parameters (report_data may be null).
     * If targetInfo is null, SGX returns the report for the enclave itself.
     */
    if (!report)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (targetInfoSize > sizeof(sgx_target_info_t) ||
        report_data_size > sizeof(sgx_report_data_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (targetInfo != NULL)
        oe_memcpy(&ti, targetInfo, targetInfoSize);

    if (report_data != NULL)
        oe_memcpy(&rd, report_data, report_data_size);

    oe_memset(&r, 0, sizeof(sgx_report_t));

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(&ti), "c"(&rd), "d"(&r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    oe_memcpy(report, &r, sizeof(sgx_report_t));

    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_local_report(
    const void* report_data,
    size_t report_data_size,
    const void* optParams,
    size_t optParamsSize,
    void* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;

    if (report_data_size > OE_REPORT_DATA_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // optParams may be null, in which case SGX returns the report for the
    // enclave itself.
    if (optParams == NULL && optParamsSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // If supplied, it must be a valid sgx_target_info_t.
    if (optParams != NULL && optParamsSize != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    // An sgx_report_t will be filled into the report buffer.
    if (reportBufferSize == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // When supplied buffer is small, report the expected buffer size so that
    // the user can create correctly sized buffer and call oe_get_report again.
    if (reportBuffer == NULL || *reportBufferSize < sizeof(sgx_report_t))
    {
        *reportBufferSize = sizeof(sgx_report_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(
        sgx_create_report(
            report_data,
            report_data_size,
            optParams,
            optParamsSize,
            reportBuffer));

    *reportBufferSize = sizeof(sgx_report_t);
    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_sgx_target_info(sgx_target_info_t* targetInfo)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_qetarget_info_args_t* args =
        (oe_get_qetarget_info_args_t*)oe_host_calloc(1, sizeof(*args));
    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_ocall(OE_OCALL_GET_QE_TARGET_INFO, (uint64_t)args, NULL));

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
    const sgx_report_t* sgxReport,
    uint8_t* quote,
    size_t* quoteSize)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t argSize = sizeof(oe_get_qetarget_info_args_t);

    // If quote buffer is NULL, then ignore passed in quoteSize value.
    // This treats scenarios where quote == NULL and *quoteSize == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quoteSize = 0;

    // Allocate memory for args structure + quote buffer.
    argSize += *quoteSize;

    oe_get_quote_args_t* args =
        (oe_get_quote_args_t*)oe_host_calloc(1, argSize);
    args->sgxReport = *sgxReport;
    args->quoteSize = *quoteSize;

    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_ocall(OE_OCALL_GET_QUOTE, (uint64_t)args, NULL));
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
    const uint8_t* report_data,
    size_t report_data_size,
    const void* optParams,
    size_t optParamsSize,
    uint8_t* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t sgxTargetInfo = {{0}};
    sgx_report_t sgxReport = {{{0}}};
    size_t sgxReportSize = sizeof(sgxReport);
    sgx_quote_t* sgxQuote = NULL;

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
        _oe_get_local_report(
            report_data,
            report_data_size,
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
    if (*reportBufferSize < sizeof(sgx_quote_t))
        OE_RAISE(OE_UNEXPECTED);

    sgxQuote = (sgx_quote_t*)reportBuffer;

    // Ensure that report is within acceptable size.
    if (*reportBufferSize > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_UNEXPECTED);

    if (oe_memcmp(
            &sgxQuote->report_body, &sgxReport.body, sizeof(sgxReport.body)) !=
        0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:

    return result;
}

oe_result_t oe_get_report(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* optParams,
    size_t optParamsSize,
    uint8_t* reportBuffer,
    size_t* reportBufferSize)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* header = (oe_report_header_t*)reportBuffer;

    // Reserve space in the buffer for header.
    // reportBuffer and reportBufferSize are both trusted.
    if (reportBuffer && reportBufferSize)
    {
        if (*reportBufferSize >= sizeof(oe_report_header_t))
        {
            reportBuffer += sizeof(oe_report_header_t);
            *reportBufferSize -= sizeof(oe_report_header_t);
        }
    }

    if (flags & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
    {
        OE_CHECK(
            _oe_get_remote_report(
                report_data,
                report_data_size,
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
                report_data,
                report_data_size,
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

oe_result_t _HandleGetSgxReport(uint64_t argIn)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_report_args_t* hostArg = (oe_get_sgx_report_args_t*)argIn;
    oe_get_sgx_report_args_t encArg;
    size_t reportBufferSize = sizeof(sgx_report_t);

    if (hostArg == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Validate and copy args to prevent TOCTOU issues.
    encArg = *hostArg;

    // Host is not allowed to pass report data. Otherwise, the host can use the
    // enclave to put whatever data it wants in a report. The data field is
    // intended to be used for digital signatures and is not allowed to be
    // tampered with by the host.
    OE_CHECK(
        _oe_get_local_report(
            NULL,
            0,
            (encArg.optParamsSize != 0) ? encArg.optParams : NULL,
            encArg.optParamsSize,
            (uint8_t*)&encArg.sgxReport,
            &reportBufferSize));

    *hostArg = encArg;
    result = OE_OK;

done:
    if (hostArg)
        hostArg->result = result;
    return result;
}
