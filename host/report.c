// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../common/quote.h"
#include "quote.h"

#if defined(OE_USE_LIBSGX)
#include "sgxquoteprovider.h"
#endif

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _oe_get_local_report(
    oe_enclave_t* enclave,
    const void* opt_params,
    size_t opt_params_size,
    void* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_report_args_t* arg = NULL;

    // opt_params, if specified, must be a sgx_target_info_t. When opt_params is
    // NULL, opt_params_size must be zero.
    if (opt_params != NULL && opt_params_size != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (opt_params == NULL && opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer == NULL || *report_buffer_size < sizeof(sgx_report_t))
    {
        *report_buffer_size = sizeof(sgx_report_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (opt_params != NULL)
        OE_CHECK(
            oe_memcpy_s(
                arg->opt_params, opt_params_size, opt_params, opt_params_size));

    arg->opt_params_size = opt_params_size;

    OE_CHECK(oe_ecall(enclave, OE_ECALL_GET_SGX_REPORT, (uint64_t)arg, NULL));

    OE_CHECK(
        oe_memcpy_s(
            report_buffer,
            *report_buffer_size,
            &arg->sgx_report,
            sizeof(sgx_report_t)));
    *report_buffer_size = sizeof(sgx_report_t);
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
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t* sgx_target_info = NULL;
    sgx_report_t* sgx_report = NULL;
    size_t sgx_report_size = sizeof(sgx_report_t);

    // For remote attestation, the Quoting Enclave's target info is used.
    // opt_params must not be supplied.
    if (opt_params != NULL || opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_buffer == NULL)
        *report_buffer_size = 0;

    /*
     * Get target info from Quoting Enclave.
     */
    sgx_target_info = calloc(1, sizeof(sgx_target_info_t));

    if (sgx_target_info == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(sgx_get_qetarget_info(sgx_target_info));

    /*
     * Get sgx_report_t from the enclave.
     */
    sgx_report = (sgx_report_t*)calloc(1, sizeof(sgx_report_t));

    if (sgx_report == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(
        _oe_get_local_report(
            enclave,
            sgx_target_info,
            sizeof(*sgx_target_info),
            (uint8_t*)sgx_report,
            &sgx_report_size));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(sgx_get_quote(sgx_report, report_buffer, report_buffer_size));

    result = OE_OK;

done:

    if (sgx_target_info)
    {
        oe_secure_zero_fill(sgx_target_info, sizeof(*sgx_target_info));
        free(sgx_target_info);
    }

    if (sgx_report)
    {
        oe_secure_zero_fill(sgx_report, sizeof(*sgx_report));
        free(sgx_report);
    }

    return result;
}

oe_result_t oe_get_report(
    oe_enclave_t* enclave,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* header = (oe_report_header_t*)report_buffer;

#if defined(OE_USE_LIBSGX)
    // The two host side attestation API's are oe_get_report and
    // oe_verify_report. Initialize the quote provider in both these APIs.
    OE_CHECK(oe_initialize_quote_provider());
#endif

    // Reserve space in the buffer for header.
    if (report_buffer && report_buffer_size)
    {
        if (*report_buffer_size >= sizeof(oe_report_header_t))
        {
            OE_CHECK(
                oe_safe_add_u64(
                    (uint64_t)report_buffer,
                    sizeof(oe_report_header_t),
                    (uint64_t*)&report_buffer));
            *report_buffer_size -= sizeof(oe_report_header_t);
        }
    }

    if (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
    {
        OE_CHECK(
            _oe_get_remote_report(
                enclave,
                opt_params,
                opt_params_size,
                report_buffer,
                report_buffer_size));
    }
    else
    {
        // If no flags are specified, default to locally attestable report.
        OE_CHECK(
            _oe_get_local_report(
                enclave,
                opt_params,
                opt_params_size,
                report_buffer,
                report_buffer_size));
    }

    header->version = OE_REPORT_HEADER_VERSION;
    header->report_type = (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
                              ? OE_REPORT_TYPE_SGX_REMOTE
                              : OE_REPORT_TYPE_SGX_LOCAL;
    header->report_size = *report_buffer_size;
    OE_CHECK(
        oe_safe_add_u64(
            *report_buffer_size,
            sizeof(oe_report_header_t),
            report_buffer_size));
    result = OE_OK;

done:
    if (result == OE_BUFFER_TOO_SMALL)
    {
        *report_buffer_size += sizeof(oe_report_header_t);
    }

    return result;
}

oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_verify_report_args_t arg = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

#if defined(OE_USE_LIBSGX)
    // The two host side attestation API's are oe_get_report and
    // oe_verify_report. Initialize the quote provider in both these APIs.
    OE_CHECK(oe_initialize_quote_provider());
#endif

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

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
        arg.report_size = report_size;
        arg.result = OE_FAILURE;

        // Call enclave to verify the report. Do not ask the enclave to return a
        // parsed report since the parsed report will then contain pointers to
        // enclave memory. Instead, pass NULL as the optional parsed_report out
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
    if (parsed_report != NULL)
        OE_CHECK(oe_parse_report(report, report_size, parsed_report));

    result = OE_OK;
done:
    return result;
}
