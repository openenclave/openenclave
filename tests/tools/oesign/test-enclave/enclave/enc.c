// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
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
