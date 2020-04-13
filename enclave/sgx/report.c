// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "report.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgxkeys.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include "../common/sgx/quote.h"
#include "platform_t.h"

OE_STATIC_ASSERT(OE_REPORT_DATA_SIZE == sizeof(sgx_report_data_t));

static oe_result_t _get_report_key(
    const sgx_report_t* sgx_report,
    sgx_key_t* sgx_key)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_key_request_t sgx_key_request = {0};

    sgx_key_request.key_name = SGX_KEYSELECT_REPORT;
    OE_CHECK(oe_memcpy_s(
        sgx_key_request.key_id,
        sizeof(sgx_key_request.key_id),
        sgx_report->keyid,
        sizeof(sgx_report->keyid)));

    OE_CHECK(oe_get_key(&sgx_key_request, sgx_key));
    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgx_key_request, sizeof(sgx_key_request));

    return result;
}

// oe_verify_report needs crypto library's cmac computation. oecore does not
// have crypto functionality. Hence oe_verify_report is implemented here instead
// of in oecore. Also see ECall_HandleVerifyReport below.
oe_result_t oe_verify_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    sgx_key_t sgx_key = {{0}};
    oe_report_header_t* header = (oe_report_header_t*)report;

    sgx_report_t* sgx_report = NULL;

    const size_t aes_cmac_length = sizeof(sgx_key);
    oe_aes_cmac_t report_aes_cmac = {{0}};
    oe_aes_cmac_t computed_aes_cmac = {{0}};

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
        OE_CHECK(oe_verify_sgx_quote(
            header->report, header->report_size, NULL, 0, NULL));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        sgx_report = (sgx_report_t*)header->report;

        OE_CHECK(_get_report_key(sgx_report, &sgx_key));

        OE_CHECK(oe_aes_cmac_sign(
            (uint8_t*)&sgx_key,
            sizeof(sgx_key),
            (uint8_t*)&sgx_report->body,
            sizeof(sgx_report->body),
            &computed_aes_cmac));

        // Fetch cmac from sgx_report.
        // Note: sizeof(sgx_report->mac) <= sizeof(oe_aes_cmac_t).
        oe_secure_memcpy(&report_aes_cmac, sgx_report->mac, aes_cmac_length);

        if (!oe_secure_aes_cmac_equal(&computed_aes_cmac, &report_aes_cmac))
            OE_RAISE(OE_VERIFY_FAILED_AES_CMAC_MISMATCH);
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Optionally return parsed report.
    if (parsed_report != NULL)
        *parsed_report = oe_report;

    result = OE_OK;

done:
    // Cleanup secret.
    oe_secure_zero_fill(&sgx_key, sizeof(sgx_key));

    return result;
}

oe_result_t oe_verify_report_ecall(const void* report, size_t report_size)
{
    return oe_verify_report(report, report_size, NULL);
}
