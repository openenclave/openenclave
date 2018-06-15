// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>

#ifdef OE_BUILD_ENCLAVE

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>

#define Memset oe_memset
#define Memcpy oe_memcpy

#else

#include <openenclave/host.h>
#include <stdio.h>

#define Memset memset
#define Memcpy memcpy

#endif

static void _oe_parse_sgx_report_body(
    const sgx_report_body_t* report_body,
    bool remote,
    oe_report_t* parsed_report)
{
    Memset(parsed_report, 0, sizeof(oe_report_t));

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
    Memcpy(
        parsed_report->identity.unique_id,
        report_body->mrenclave,
        sizeof(report_body->mrenclave));

    OE_STATIC_ASSERT(
        sizeof(parsed_report->identity.author_id) >=
        sizeof(report_body->mrsigner));
    Memcpy(
        parsed_report->identity.author_id,
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
    uint32_t report_size,
    oe_report_t* parsed_report)
{
    const sgx_report_t* sgx_report = NULL;
    const sgx_quote_t* sgx_quote = NULL;
    oe_result_t result = OE_OK;

    if (report == NULL || parsed_report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == sizeof(sgx_report_t))
    {
        sgx_report = (const sgx_report_t*)report;
        _oe_parse_sgx_report_body(&sgx_report->body, false, parsed_report);
    }
    else if (report_size >= sizeof(sgx_quote_t))
    {
        sgx_quote = (const sgx_quote_t*)report;
        _oe_parse_sgx_report_body(&sgx_quote->report_body, true, parsed_report);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

done:
    return result;
}
