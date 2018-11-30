/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>
#include <stdlib.h>

#include <sgx_utils.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>

#include "../include/tcps.h"

#ifndef _In_
#include "sal_unsup.h"
#endif

static void fill_sgx_target_info(
    _In_ const sgx_report_t* sgx_report,
    _Out_ sgx_target_info_t* info)
{
    memset(info, 0, sizeof(*info));

    info->mr_enclave = sgx_report->body.mr_enclave;
    info->attributes = sgx_report->body.attributes;
    info->misc_select = sgx_report->body.misc_select;
}

oe_result_t oe_get_target_info_v2(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Outptr_ void** target_info_buffer,
    _Out_ size_t* target_info_size)
{
    sgx_report_t* sgx_report = (sgx_report_t*)report;
    sgx_target_info_t* info;

    if (report == NULL || report_size < sizeof(*sgx_report) ||
        target_info_size == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    info = (sgx_target_info_t*)malloc(sizeof(*info));
    if (info == NULL)
    {
        return OE_OUT_OF_MEMORY;
    }

    fill_sgx_target_info(sgx_report, info);

    *target_info_buffer = info;
    *target_info_size = sizeof(*info);
    return OE_OK;
}

void oe_free_target_info(_In_ void* target_info_buffer)
{
    free(target_info_buffer);
}

oe_result_t oe_get_target_info_v1(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_writes_bytes_(*target_info_size) void* target_info_buffer,
    _Inout_ size_t* target_info_size)
{
    sgx_report_t* sgx_report = (sgx_report_t*)report;
    sgx_target_info_t* info = (sgx_target_info_t*)target_info_buffer;

    if (report == NULL || report_size < sizeof(*sgx_report) ||
        target_info_size == NULL)
    {
        return OE_INVALID_PARAMETER;
    }

    if (target_info_buffer == NULL || *target_info_size < sizeof(*info))
    {
        *target_info_size = sizeof(*info);
        return OE_BUFFER_TOO_SMALL;
    }

    fill_sgx_target_info(sgx_report, info);

    *target_info_size = sizeof(*info);
    return OE_OK;
}

oe_result_t oe_parse_report(
    _In_reads_bytes_(report_size) const uint8_t* report,
    _In_ size_t report_size,
    _Out_ oe_report_t* parsed_report)
{
    if (report_size != sizeof(sgx_report_t))
    {
        return OE_INVALID_PARAMETER;
    }

    const sgx_report_t* sgxReport = (sgx_report_t*)report;
    parsed_report->size = sizeof(*parsed_report);
    parsed_report->type = OE_ENCLAVE_TYPE_DEFAULT;

    parsed_report->enclave_report_size = sizeof(sgxReport->body);
    parsed_report->enclave_report = (uint8_t*)&sgxReport->body;

    parsed_report->report_data_size = sizeof(sgxReport->body.report_data);
    parsed_report->report_data = (uint8_t*)sgxReport->body.report_data.d;

    parsed_report->identity.id_version = 0;
    parsed_report->identity.security_version = sgxReport->body.isv_svn;

    parsed_report->identity.attributes = 0;
    if (sgxReport->body.attributes.flags & SGX_FLAGS_DEBUG)
    {
        parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_DEBUG;
    }

    // TODO: add support for OE_REPORT_ATTRIBUTES_REMOTE

    memcpy(
        parsed_report->identity.unique_id,
        sgxReport->body.mr_enclave.m,
        OE_UNIQUE_ID_SIZE);

    memcpy(
        parsed_report->identity.signer_id,
        sgxReport->body.mr_signer.m,
        OE_SIGNER_ID_SIZE);

    // OE_PRODUCT_ID_SIZE is 16 bytes, but in the Intel SGX SDK,
    // isv_prod_id is only 16 bits.
    memset(parsed_report->identity.product_id, 0, OE_PRODUCT_ID_SIZE);
    memcpy(
        parsed_report->identity.product_id,
        &sgxReport->body.isv_prod_id,
        sizeof(sgx_prod_id_t));

    return OE_OK;
}
