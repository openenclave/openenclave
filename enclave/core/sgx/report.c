// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/safecrt.h>
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
    const void* target_info,
    size_t target_info_size,
    sgx_report_t* report)
{
    oe_result_t result = OE_UNEXPECTED;

    // Allocate aligned objects as required by EREPORT instruction.
    sgx_target_info_t ti OE_ALIGNED(512) = {{0}};
    sgx_report_data_t rd OE_ALIGNED(128) = {{0}};
    sgx_report_t r OE_ALIGNED(512) = {{{0}}};

    /*
     * Reject invalid parameters (report_data may be null).
     * If target_info is null, SGX returns the report for the enclave itself.
     */
    if (!report)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (target_info_size > sizeof(sgx_target_info_t) ||
        report_data_size > sizeof(sgx_report_data_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (target_info != NULL)
        OE_CHECK(
            oe_memcpy_s(
                &ti, sizeof(sgx_target_info_t), target_info, target_info_size));

    if (report_data != NULL)
        OE_CHECK(
            oe_memcpy_s(
                &rd, sizeof(sgx_report_data_t), report_data, report_data_size));

    /* Invoke EREPORT instruction */
    asm volatile(
        "ENCLU"
        :
        : "a"(ENCLU_EREPORT), "b"(&ti), "c"(&rd), "d"(&r)
        : "memory");

    /* Copy REPORT to caller's buffer */
    OE_CHECK(
        oe_memcpy_s(report, sizeof(sgx_report_t), &r, sizeof(sgx_report_t)));

    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_local_report(
    const void* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    void* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (report_data_size > OE_REPORT_DATA_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // opt_params may be null, in which case SGX returns the report for the
    // enclave itself.
    if (opt_params == NULL && opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // If supplied, it must be a valid sgx_target_info_t.
    if (opt_params != NULL && opt_params_size != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    // An sgx_report_t will be filled into the report buffer.
    if (report_buffer_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // When supplied buffer is small, report the expected buffer size so that
    // the user can create correctly sized buffer and call oe_get_report again.
    if (report_buffer == NULL || *report_buffer_size < sizeof(sgx_report_t))
    {
        *report_buffer_size = sizeof(sgx_report_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(
        sgx_create_report(
            report_data,
            report_data_size,
            opt_params,
            opt_params_size,
            report_buffer));

    *report_buffer_size = sizeof(sgx_report_t);
    result = OE_OK;

done:

    return result;
}

static oe_result_t _oe_get_sgx_target_info(sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_qetarget_info_args_t* args =
        (oe_get_qetarget_info_args_t*)oe_host_calloc(1, sizeof(*args));
    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_ocall(OE_OCALL_GET_QE_TARGET_INFO, (uint64_t)args, NULL));

    result = args->result;
    if (result == OE_OK)
        *target_info = args->target_info;

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
    const sgx_report_t* sgx_report,
    uint8_t* quote,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t arg_size = sizeof(oe_get_qetarget_info_args_t);

    // If quote buffer is NULL, then ignore passed in quote_size value.
    // This treats scenarios where quote == NULL and *quote_size == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quote_size = 0;

    // Allocate memory for args structure + quote buffer.
    arg_size += *quote_size;

    oe_get_quote_args_t* args =
        (oe_get_quote_args_t*)oe_host_calloc(1, arg_size);
    args->sgx_report = *sgx_report;
    args->quote_size = *quote_size;

    if (args == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_ocall(OE_OCALL_GET_QUOTE, (uint64_t)args, NULL));
    result = args->result;

    if (result == OE_OK || result == OE_BUFFER_TOO_SMALL)
        *quote_size = args->quote_size;

    if (result == OE_OK)
        OE_CHECK(oe_memcpy_s(quote, *quote_size, args->quote, *quote_size));

done:
    if (args)
    {
        oe_secure_zero_fill(args, arg_size);
        oe_host_free(args);
    }

    return result;
}

oe_result_t oe_get_remote_report(
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t sgx_target_info = {{0}};
    sgx_report_t sgx_report = {{{0}}};
    size_t sgx_report_size = sizeof(sgx_report);
    sgx_quote_t* sgx_quote = NULL;

    // For remote attestation, the Quoting Enclave's target info is used.
    // opt_params must not be supplied.
    if (opt_params != NULL || opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * OCall: Get target info from Quoting Enclave.
     * This involves a call to host. The target provided by targetinfo does not
     * need to be trusted because returning a report is not an operation that
     * requires privacy. The trust decision is one of integrity verification
     * on the part of the report recipient.
     */
    OE_CHECK(_oe_get_sgx_target_info(&sgx_target_info));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_CHECK(
        _oe_get_local_report(
            report_data,
            report_data_size,
            &sgx_target_info,
            sizeof(sgx_target_info),
            &sgx_report,
            &sgx_report_size));

    /*
     * OCall: Get the quote for the local report.
     */
    OE_CHECK(_oe_get_quote(&sgx_report, report_buffer, report_buffer_size));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (*report_buffer_size < sizeof(sgx_quote_t))
        OE_RAISE(OE_UNEXPECTED);

    sgx_quote = (sgx_quote_t*)report_buffer;

    // Ensure that report is within acceptable size.
    if (*report_buffer_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_UNEXPECTED);

    if (oe_memcmp(
            &sgx_quote->report_body,
            &sgx_report.body,
            sizeof(sgx_report.body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:

    return result;
}

oe_result_t oe_get_report(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* header = (oe_report_header_t*)report_buffer;

    // Reserve space in the buffer for header.
    // report_buffer and report_buffer_size are both trusted.
    if (report_buffer && report_buffer_size)
    {
        if (*report_buffer_size >= sizeof(oe_report_header_t))
        {
            report_buffer += sizeof(oe_report_header_t);
            *report_buffer_size -= sizeof(oe_report_header_t);
        }
    }

    if (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
    {
        OE_CHECK(
            oe_get_remote_report(
                report_data,
                report_data_size,
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
                report_data,
                report_data_size,
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

oe_result_t _handle_get_sgx_report(uint64_t arg_in)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_report_args_t* host_arg = (oe_get_sgx_report_args_t*)arg_in;
    oe_get_sgx_report_args_t enc_arg;
    size_t report_buffer_size = sizeof(sgx_report_t);

    if (host_arg == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Validate and copy args to prevent TOCTOU issues.
    enc_arg = *host_arg;

    // Host is not allowed to pass report data. Otherwise, the host can use the
    // enclave to put whatever data it wants in a report. The data field is
    // intended to be used for digital signatures and is not allowed to be
    // tampered with by the host.
    OE_CHECK(
        _oe_get_local_report(
            NULL,
            0,
            (enc_arg.opt_params_size != 0) ? enc_arg.opt_params : NULL,
            enc_arg.opt_params_size,
            (uint8_t*)&enc_arg.sgx_report,
            &report_buffer_size));

    *host_arg = enc_arg;
    result = OE_OK;

done:
    if (host_arg)
        host_arg->result = result;
    return result;
}
