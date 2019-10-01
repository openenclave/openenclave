// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/host.h>
#include <openenclave/host_verify.h>
#include <openenclave/internal/raise.h>

#include "../../common/sgx/quote.h"
#include "sgxquoteprovider.h"

oe_result_t oe_verify_remote_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* input_validation_time)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // The two host side attestation API's are oe_get_report and
    // oe_verify_report. Initialize the quote provider in both these APIs.
    OE_CHECK(oe_initialize_quote_provider());

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type != OE_REPORT_TYPE_SGX_REMOTE)
        OE_RAISE(OE_UNSUPPORTED);

    // Quote attestation can be done entirely on the host side.
    OE_CHECK(oe_verify_quote_internal_with_collaterals(
        header->report,
        header->report_size,
        collaterals,
        collaterals_size,
        input_validation_time));

    // Optionally return parsed report.
    if (parsed_report != NULL)
        OE_CHECK(oe_parse_report(report, report_size, parsed_report));

    result = OE_OK;

done:
    return result;
}