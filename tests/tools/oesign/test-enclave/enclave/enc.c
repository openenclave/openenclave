// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/report.h>
#include <stdio.h>
#include <string.h>
#include "oesign_test_t.h"

bool is_test_signed()
{
    static const uint8_t OE_DEFAULT_DEBUG_SIGNED_MRSIGNER[] = {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
        0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
        0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

    bool is_test_signed = false;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report_data = NULL;
    size_t report_size = 0;
    oe_report_t report;
    const size_t mrsigner_hex_length =
        sizeof(report.identity.signer_id) * 2 + 1;
    char mrsigner_hex[mrsigner_hex_length];

    OE_STATIC_ASSERT(
        sizeof(OE_DEFAULT_DEBUG_SIGNED_MRSIGNER) ==
        sizeof(report.identity.signer_id));

    result = oe_get_report(0, NULL, 0, NULL, 0, &report_data, &report_size);
    if (result == OE_OK)
    {
        result = oe_parse_report(report_data, report_size, &report);
        if (result == OE_OK)
        {
            oe_hex_string(
                mrsigner_hex,
                mrsigner_hex_length,
                report.identity.signer_id,
                sizeof(report.identity.signer_id));

            printf("Enclave MRSIGNER = %s\n", mrsigner_hex);

            is_test_signed =
                (memcmp(
                     report.identity.signer_id,
                     OE_DEFAULT_DEBUG_SIGNED_MRSIGNER,
                     sizeof(report.identity.signer_id)) != 0);
        }

        oe_free_report(report_data);
    }

    return is_test_signed;
}

oe_result_t check_kss_extended_ids(
    oe_uuid_t* family_id,
    oe_uuid_t* ext_product_id)
{
    /* Null-terminated hex string buffer size with 2 char per byte */
    const size_t OE_KSS_ID_HEX_BUFFER_SIZE = sizeof(oe_uuid_t) * 2 + 1;

    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_header_t* header = NULL;
    sgx_quote_t* quote = NULL;
    uint64_t quote_size = 0;

    char isvid_hex[OE_KSS_ID_HEX_BUFFER_SIZE];

    printf("========== Getting report with KSS feature\n");

    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        0,
        NULL,
        0,
        (uint8_t**)&remote_report,
        &report_size);

    if (result == OE_OK)
    {
        printf("========== Got report, size = %zu\n", report_size);

        header = (oe_report_header_t*)remote_report;
        quote = (sgx_quote_t*)header->report;

        quote_size = header->report_size;

        sgx_report_body_t* report_body =
            (sgx_report_body_t*)&quote->report_body;

        oe_hex_string(
            isvid_hex,
            OE_KSS_ID_HEX_BUFFER_SIZE,
            report_body->isvfamilyid,
            sizeof(report_body->isvfamilyid));
        printf("Enclave ISV Family ID = %s\n", isvid_hex);

        oe_hex_string(
            isvid_hex,
            OE_KSS_ID_HEX_BUFFER_SIZE,
            report_body->isvextprodid,
            sizeof(report_body->isvextprodid));
        printf("Enclave ISV Extended ProductID = %s\n", isvid_hex);

        if (!memcmp(report_body->isvfamilyid, &family_id, sizeof(oe_uuid_t))||
            !memcmp(report_body->isvextprodid, &ext_product_id, sizeof(oe_uuid_t)))
            result = OE_REPORT_PARSE_ERROR;
    }
    oe_free_report(remote_report);

    return result;
}
