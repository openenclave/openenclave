// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/utils.h>
#include "platform_t.h"

/**
 * Declare the prototypes of the following functions to avoid the
 * missing-prototypes warning.
 */
oe_result_t _oe_get_qetarget_info_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info);
oe_result_t _oe_get_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out);

/**
 * Make the following OCALLs weak to support the system EDL opt-in.
 * When the user does not opt into (import) the EDL, the linker will pick
 * the following default implementations. If the user opts into the EDL,
 * the implementations (which are strong) in the oeedger8r-generated code will
 * be used.
 */
oe_result_t _oe_get_qetarget_info_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info)
{
    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(target_info);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_get_qetarget_info_ocall, oe_get_qetarget_info_ocall);

oe_result_t _oe_get_quote_ocall(
    oe_result_t* _retval,
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out)
{
    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(sgx_report);
    OE_UNUSED(quote);
    OE_UNUSED(quote_size);
    OE_UNUSED(quote_size_out);

    if (_retval)
        *_retval = OE_UNSUPPORTED;

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_get_quote_ocall, oe_get_quote_ocall);

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
        OE_CHECK(oe_memcpy_s(
            &ti, sizeof(sgx_target_info_t), target_info, target_info_size));

    if (report_data != NULL)
        OE_CHECK(oe_memcpy_s(
            &rd, sizeof(sgx_report_data_t), report_data, report_data_size));

    /* Invoke EREPORT instruction */
    asm volatile("ENCLU"
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

static oe_result_t _get_local_report(
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
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(sgx_create_report(
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

static oe_result_t _get_sgx_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t retval;

    OE_CHECK(oe_get_qetarget_info_ocall(
        &retval, format_id, opt_params, opt_params_size, target_info));
    result = (oe_result_t)retval;

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "SGX remote attestation is not enabled. To "
            "enable, please add\n\n"
            "from \"openenclave/edl/sgx/attestation.edl\" import *;\n\n"
            "in the edl file.\n");
    return result;
}

static oe_result_t _get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    uint8_t* quote,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t retval;

    // If quote buffer is NULL, then ignore passed in quote_size value.
    // This treats scenarios where quote == NULL and *quote_size == large-value
    // as OE_BUFFER_TOO_SMALL.
    if (quote == NULL)
        *quote_size = 0;

    OE_CHECK(oe_get_quote_ocall(
        &retval,
        format_id,
        opt_params,
        opt_params_size,
        sgx_report,
        quote,
        *quote_size,
        quote_size));
    result = (oe_result_t)retval;

done:
    if (result == OE_UNSUPPORTED)
        OE_TRACE_WARNING(
            "SGX remote attestation is not enabled. To "
            "enable, please add\n\n"
            "from \"openenclave/edl/sgx/attestation.edl\" import *;\n\n"
            "in the edl file.\n");
    return result;
}

oe_result_t oe_get_remote_report(
    const oe_uuid_t* format_id,
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

    /*
     * OCall: Get target info from Quoting Enclave.
     * This involves a call to host. The target provided by targetinfo does not
     * need to be trusted because returning a report is not an operation that
     * requires privacy. The trust decision is one of integrity verification
     * on the part of the report recipient.
     */
    OE_CHECK(_get_sgx_target_info(
        format_id, opt_params, opt_params_size, &sgx_target_info));

    /*
     * Get enclave's local report passing in the quoting enclave's target info.
     */
    OE_CHECK(_get_local_report(
        report_data,
        report_data_size,
        &sgx_target_info,
        sizeof(sgx_target_info),
        &sgx_report,
        &sgx_report_size));

    /*
     * OCall: Get the quote for the local report.
     */
    result = _get_quote(
        format_id,
        opt_params,
        opt_params_size,
        &sgx_report,
        report_buffer,
        report_buffer_size);
    if (result == OE_BUFFER_TOO_SMALL)
        OE_CHECK_NO_TRACE(result);
    else
        OE_CHECK(result);

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (*report_buffer_size < sizeof(sgx_quote_t))
        OE_RAISE(OE_UNEXPECTED);

    sgx_quote = (sgx_quote_t*)report_buffer;

    if (sgx_quote == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that report is within acceptable size.
    if (*report_buffer_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_UNEXPECTED);

    if (memcmp(
            &sgx_quote->report_body,
            &sgx_report.body,
            sizeof(sgx_report.body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:

    return result;
}

static oe_result_t _oe_get_report_internal(
    uint32_t flags,
    const oe_uuid_t* format_id,
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
        result = oe_get_remote_report(
            format_id,
            report_data,
            report_data_size,
            opt_params,
            opt_params_size,
            report_buffer,
            report_buffer_size);
    }
    else
    {
        // If no flags are specified, default to locally attestable report.
        result = _get_local_report(
            report_data,
            report_data_size,
            opt_params,
            opt_params_size,
            report_buffer,
            report_buffer_size);
    }
    if (result == OE_BUFFER_TOO_SMALL)
        OE_CHECK_NO_TRACE(result);
    else
        OE_CHECK(result);

    header->version = OE_REPORT_HEADER_VERSION;
    header->report_type = (flags & OE_REPORT_FLAGS_REMOTE_ATTESTATION)
                              ? OE_REPORT_TYPE_SGX_REMOTE
                              : OE_REPORT_TYPE_SGX_LOCAL;
    header->report_size = *report_buffer_size;
    OE_CHECK(oe_safe_add_u64(
        *report_buffer_size, sizeof(oe_report_header_t), report_buffer_size));
    result = OE_OK;

done:
    if (result == OE_BUFFER_TOO_SMALL)
    {
        *report_buffer_size += sizeof(oe_report_header_t);
    }

    return result;
}

oe_result_t oe_get_report_v2_internal(
    uint32_t flags,
    const oe_uuid_t* format_id,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* tmp_buffer = NULL;
    size_t tmp_buffer_size = 0;
    size_t out_buffer_size = 0;

    if ((report_buffer == NULL) || (report_buffer_size == NULL))
    {
        return OE_INVALID_PARAMETER;
    }

    *report_buffer = NULL;
    *report_buffer_size = 0;

    result = _oe_get_report_internal(
        flags,
        format_id,
        report_data,
        report_data_size,
        opt_params,
        opt_params_size,
        NULL,
        &tmp_buffer_size);
    if (result != OE_BUFFER_TOO_SMALL)
    {
        result = (result == OE_OK) ? OE_UNEXPECTED : result;
        OE_RAISE(result);
    }

    tmp_buffer = oe_calloc(1, tmp_buffer_size);
    if (tmp_buffer == NULL)
    {
        return OE_OUT_OF_MEMORY;
    }

    out_buffer_size = tmp_buffer_size;
    OE_CHECK(_oe_get_report_internal(
        flags,
        format_id,
        report_data,
        report_data_size,
        opt_params,
        opt_params_size,
        tmp_buffer,
        &out_buffer_size));

    if (out_buffer_size != tmp_buffer_size)
        OE_RAISE(OE_UNEXPECTED);

    *report_buffer_size = tmp_buffer_size;
    *report_buffer = tmp_buffer;
    tmp_buffer = NULL;

    result = OE_OK;

done:
    if (tmp_buffer)
        oe_free(tmp_buffer);

    return result;
}

oe_result_t oe_get_sgx_report_ecall(
    const void* opt_params,
    size_t opt_params_size,
    sgx_report_t* report)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t report_buffer_size = sizeof(sgx_report_t);

    OE_CHECK(_get_local_report(
        NULL,
        0,
        opt_params,
        opt_params_size,
        (uint8_t*)report,
        &report_buffer_size));

    result = OE_OK;

done:
    return result;
}
