/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <string.h>

#include <openenclave/enclave.h>
#include "enclavelibc.h"
#include "../oeresult.h"

#include <sgx_trts.h>
#include <sgx_utils.h>

oe_result_t oe_get_report_v2(
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    sgx_report_t sgxReport = {0};
    sgx_report_data_t* sgxReportData = NULL;
    sgx_target_info_t* sgxTargetInfo = NULL;
    sgx_status_t sgxStatus = SGX_SUCCESS;

    if (report_data_size > 0)
    {
        sgxReportData = (sgx_report_data_t*)report_data;
    }
    if (opt_params_size > 0)
    {
        sgxTargetInfo = (sgx_target_info_t*)opt_params;
    }

    if (report_data_size != 0 && report_data_size != SGX_REPORT_DATA_SIZE)
    {
        return OE_INVALID_PARAMETER;
    }
    if (opt_params_size != 0 && opt_params_size != sizeof(sgx_target_info_t))
    {
        return OE_INVALID_PARAMETER;
    }

    sgxStatus = sgx_create_report(sgxTargetInfo, sgxReportData, &sgxReport);
    if (sgxStatus != SGX_SUCCESS)
    {
        oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
        return oeResult;
    }

    if (sgxTargetInfo == NULL)
    {
        // When a report is generated with NULL target info, the MAC won't be
        // valid but it will return the target info, so call it again with the
        // target info returned.
        sgx_target_info_t targetInfo2 = {0};
        targetInfo2.attributes = sgxReport.body.attributes;
        targetInfo2.mr_enclave = sgxReport.body.mr_enclave;
        targetInfo2.misc_select = sgxReport.body.misc_select;
        sgxStatus = sgx_create_report(&targetInfo2, sgxReportData, &sgxReport);
        if (sgxStatus != SGX_SUCCESS)
        {
            oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
            return oeResult;
        }
    }

    *report_buffer = oe_malloc(sizeof(sgx_report_t));
    if (report_buffer == NULL)
    {
        return OE_OUT_OF_MEMORY;
    }
    memcpy(*report_buffer, &sgxReport, sizeof(sgxReport));
    *report_buffer_size = sizeof(sgxReport);
    return OE_OK;
}

oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t oeResult = OE_OK;
    if (report_size != sizeof(sgx_report_t))
    {
        return OE_INVALID_PARAMETER;
    }
    if (parsed_report != NULL)
    {
        oeResult = oe_parse_report(report, report_size, parsed_report);
        if (oeResult != OE_OK)
        {
            return oeResult;
        }
    }
    const sgx_report_t* sgxReport = (sgx_report_t*)report;
    sgx_status_t sgxStatus = sgx_verify_report(sgxReport);
    oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}