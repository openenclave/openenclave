// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include "../common.h"

oe_result_t oe_parse_sgx_report_body(
    const sgx_report_body_t* report_body,
    bool remote,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;

    oe_secure_zero_fill(parsed_report, sizeof(oe_report_t));

    parsed_report->size = sizeof(oe_report_t);
    parsed_report->type = OE_ENCLAVE_TYPE_SGX;

    /*
     * Parse identity.
     */
    parsed_report->identity.id_version = 0x0;
    parsed_report->identity.security_version = report_body->isvsvn;

    if (report_body->attributes.flags & SGX_FLAGS_DEBUG)
        parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_DEBUG;

    if (remote)
        parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_REMOTE;

    OE_STATIC_ASSERT(
        sizeof(parsed_report->identity.unique_id) >=
        sizeof(report_body->mrenclave));
    OE_CHECK(oe_memcpy_s(
        parsed_report->identity.unique_id,
        sizeof(parsed_report->identity.unique_id),
        report_body->mrenclave,
        sizeof(report_body->mrenclave)));

    OE_STATIC_ASSERT(
        sizeof(parsed_report->identity.signer_id) >=
        sizeof(report_body->mrsigner));

    OE_CHECK(oe_memcpy_s(
        parsed_report->identity.signer_id,
        sizeof(parsed_report->identity.signer_id),
        report_body->mrsigner,
        sizeof(report_body->mrsigner)));

    parsed_report->identity.product_id[0] =
        (uint8_t)report_body->isvprodid & 0xFF;
    parsed_report->identity.product_id[1] =
        (uint8_t)((report_body->isvprodid >> 8) & 0xFF);

    /*
     * Set pointer fields.
     */
    parsed_report->report_data = (uint8_t*)&report_body->report_data;
    parsed_report->report_data_size = sizeof(sgx_report_data_t);
    parsed_report->enclave_report = (uint8_t*)report_body;
    parsed_report->enclave_report_size = sizeof(sgx_report_body_t);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_parse_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    const sgx_report_t* sgx_report = NULL;
    const sgx_quote_t* sgx_quote = NULL;
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_result_t result = OE_FAILURE;

    if (report == NULL || parsed_report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size < sizeof(oe_report_header_t))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->version != OE_REPORT_HEADER_VERSION)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (header->report_size + sizeof(oe_report_header_t) != report_size)
        OE_RAISE(OE_INCORRECT_REPORT_SIZE);

    if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        sgx_report = (const sgx_report_t*)header->report;
        OE_CHECK(
            oe_parse_sgx_report_body(&sgx_report->body, false, parsed_report));
        result = OE_OK;
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        sgx_quote = (const sgx_quote_t*)header->report;
        OE_CHECK(oe_parse_sgx_report_body(
            &sgx_quote->report_body, true, parsed_report));
        result = OE_OK;
    }
    else
    {
        OE_RAISE(OE_REPORT_PARSE_ERROR);
    }

done:
    return result;
}

static oe_result_t _sgx_get_target_info(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size)
{
    oe_result_t result = OE_FAILURE;
    sgx_report_t* sgx_report = (sgx_report_t*)report;
    sgx_target_info_t* info = (sgx_target_info_t*)target_info_buffer;

    if (!report || report_size < sizeof(*sgx_report) || !target_info_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (target_info_buffer == NULL || *target_info_size < sizeof(*info))
    {
        *target_info_size = sizeof(*info);
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_memset_s(info, sizeof(*info), 0, sizeof(*info)));

    OE_CHECK(oe_memcpy_s(
        info->mrenclave,
        sizeof(info->mrenclave),
        sgx_report->body.mrenclave,
        sizeof(sgx_report->body.mrenclave)));

    info->attributes = sgx_report->body.attributes;
    info->misc_select = sgx_report->body.miscselect;

    *target_info_size = sizeof(*info);
    result = OE_OK;

done:
    return result;
}

static oe_result_t _oe_get_target_info_internal(
    const uint8_t* report,
    size_t report_size,
    void* target_info_buffer,
    size_t* target_info_size)
{
    oe_result_t result = OE_FAILURE;
    oe_report_header_t* report_header = (oe_report_header_t*)report;

    if (!report || report_size < sizeof(*report_header) || !target_info_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Validate the report header. */
    if (report_header->version != OE_REPORT_HEADER_VERSION)
        OE_RAISE(OE_INVALID_PARAMETER);

    report_size -= OE_OFFSETOF(oe_report_header_t, report);
    report += OE_OFFSETOF(oe_report_header_t, report);
    switch (report_header->report_type)
    {
        case OE_REPORT_TYPE_SGX_LOCAL:
        case OE_REPORT_TYPE_SGX_REMOTE:
            result = _sgx_get_target_info(
                report, report_size, target_info_buffer, target_info_size);
            if (result == OE_BUFFER_TOO_SMALL)
                OE_CHECK_NO_TRACE(result);
            else
                OE_CHECK(result);
            break;
        default:
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_target_info_v2(
    const uint8_t* report,
    size_t report_size,
    void** target_info_buffer,
    size_t* target_info_size)
{
    oe_result_t result = OE_FAILURE;
    size_t temp_size = 0;
    void* temp_info = NULL;

    if (!target_info_buffer || !target_info_size)
    {
        return OE_INVALID_PARAMETER;
    }

    *target_info_buffer = NULL;
    *target_info_size = 0;

    result =
        _oe_get_target_info_internal(report, report_size, NULL, &temp_size);
    if (result != OE_BUFFER_TOO_SMALL)
    {
        if (result == OE_OK)
        {
            /* Should not succeed! */
            result = OE_UNEXPECTED;
        }
        return result;
    }

    temp_info = oe_malloc(temp_size);
    if (temp_info == NULL)
    {
        return OE_OUT_OF_MEMORY;
    }

    result = _oe_get_target_info_internal(
        report, report_size, temp_info, &temp_size);
    if (result != OE_OK)
    {
        oe_free(temp_info);

        return result;
    }
    *target_info_size = temp_size;
    *target_info_buffer = temp_info;

    return OE_OK;
}

void oe_free_target_info(void* target_info_buffer)
{
    oe_free(target_info_buffer);
}
