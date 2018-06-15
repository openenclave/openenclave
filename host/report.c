// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/report.c"
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "quote.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _oe_get_local_report(
    oe_enclave_t* enclave,
    const void* report_data,
    uint32_t report_data_size,
    const void* opt_params,
    uint32_t opt_params_size,
    void* report_buffer,
    uint32_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_report_args_t* arg = NULL;

    /*
     * Perform basic parameters validation here on the host side. Thorough
     * validation will be done in the enclave side.
     */

    // report_data on the host side must be null.
    if (report_data != NULL || report_data_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // opt_params, if specified, must be a sgx_target_info_t. When opt_params is
    // NULL, opt_params_size must be zero.
    if (opt_params != NULL && opt_params_size != sizeof(sgx_target_info_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (opt_params == NULL && opt_params_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * Populate arg fields.
     */
    arg = calloc(1, sizeof(*arg));
    if (arg == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Request local report.
    arg->options = 0;

    if (opt_params != NULL)
        memcpy(arg->opt_params, opt_params, opt_params_size);

    arg->opt_params_size = opt_params_size;

    arg->report_buffer = report_buffer;
    arg->report_buffer_size = report_buffer_size ? *report_buffer_size : 0;

    OE_CHECK(oe_ecall(enclave, OE_FUNC_GET_REPORT, (uint64_t)arg, NULL));
    result = arg->result;

    if (report_buffer_size)
        *report_buffer_size = arg->report_buffer_size;

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
    const uint8_t* report_data,
    uint32_t report_data_size,
    const void* opt_params,
    uint32_t opt_params_size,
    uint8_t* report_buffer,
    uint32_t* report_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_target_info_t* sgx_target_info = NULL;
    sgx_report_t* sgx_report = NULL;
    uint32_t sgx_report_size = sizeof(sgx_report_t);
    oe_report_t parsed_report;

    // report_data on the host side must be null.
    if (report_data != NULL || report_data_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

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
            report_data,
            report_data_size,
            sgx_target_info,
            sizeof(*sgx_target_info),
            sgx_report,
            &sgx_report_size));

    /*
     * Get quote from Quoting Enclave.
     */
    OE_CHECK(sgx_get_quote(sgx_report, report_buffer, report_buffer_size));

    /*
     * Check that the entire report body in the returned quote matches the local
     * report.
     */
    if (oe_parse_report(report_buffer, *report_buffer_size, &parsed_report) !=
        OE_OK)
        OE_RAISE(OE_UNEXPECTED);

    if (memcmp(
            parsed_report.enclave_report,
            &sgx_report->body,
            sizeof(sgx_report->body)) != 0)
        OE_RAISE(OE_UNEXPECTED);

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
    uint32_t options,
    const uint8_t* report_data,
    uint32_t report_data_size,
    const void* opt_params,
    uint32_t opt_params_size,
    uint8_t* report_buffer,
    uint32_t* report_buffer_size)
{
    if (options & OE_REPORT_OPTIONS_REMOTE_ATTESTATION)
        return _oe_get_remote_report(
            enclave,
            report_data,
            report_data_size,
            opt_params,
            opt_params_size,
            report_buffer,
            report_buffer_size);

    // If no options are specified, default to local report.
    return _oe_get_local_report(
        enclave,
        report_data,
        report_data_size,
        opt_params,
        opt_params_size,
        report_buffer,
        report_buffer_size);
}

oe_result_t oe_verify_report(
    oe_enclave_t* enclave,
    const uint8_t* report,
    uint32_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_verify_report_args_t arg = {0};

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    arg.report = (uint8_t*)report;
    arg.report_size = report_size;
    arg.result = OE_FAILURE;

    // Call enclave to verify the report. Do not ask the enclave to return a
    // parsed report since the parsed report will then contain pointers to
    // enclave memory. Instead, pass NULL as the optional parsed_report out
    // parameter and parse the report below if requested.
    OE_CHECK(oe_ecall(enclave, OE_FUNC_VERIFY_REPORT, (uint64_t)&arg, NULL));
    OE_CHECK(arg.result);

    // Optionally return parsed report.
    if (parsed_report != NULL)
        OE_CHECK(oe_parse_report(report, report_size, parsed_report));

    result = OE_OK;
done:

    return result;
}
