// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include "common.h"

static void _oe_parse_sgx_report_body(
    const sgx_report_body_t* report_body,
    bool remote,
    oe_report_t* parsed_report)
{
    memset(parsed_report, 0, sizeof(oe_report_t));

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
    memcpy(
        parsed_report->identity.unique_id,
        report_body->mrenclave,
        sizeof(report_body->mrenclave));

    OE_STATIC_ASSERT(
        sizeof(parsed_report->identity.signer_id) >=
        sizeof(report_body->mrsigner));

    memcpy(
        parsed_report->identity.signer_id,
        report_body->mrsigner,
        sizeof(report_body->mrsigner));

    parsed_report->identity.product_id[0] = report_body->isvprodid & 0xFF;
    parsed_report->identity.product_id[1] = (report_body->isvprodid >> 8) & 0xFF;

    /*
     * Set pointer fields.
     */
    parsed_report->report_data = (uint8_t*)&report_body->report_data;
    parsed_report->report_data_size = sizeof(sgx_report_data_t);
    parsed_report->enclave_report = (uint8_t*)report_body;
    parsed_report->enclave_report_size = sizeof(sgx_report_body_t);
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
        OE_RAISE(OE_FAILURE);

    if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        sgx_report = (const sgx_report_t*)header->report;
        _oe_parse_sgx_report_body(&sgx_report->body, false, parsed_report);
        result = OE_OK;
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        sgx_quote = (const sgx_quote_t*)header->report;
        _oe_parse_sgx_report_body(&sgx_quote->report_body, true, parsed_report);
        result = OE_OK;
    }
    else
    {
        OE_RAISE(OE_REPORT_PARSE_ERROR);
    }

done:
    return result;
}
