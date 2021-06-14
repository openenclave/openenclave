// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "cert_verify_config.h"

oe_result_t verify_claim_value(const oe_claim_t* claim)
{
    oe_result_t result = OE_FAILURE;
    printf(TLS_ENCLAVE "\nverify unique_id:\n");
    for (size_t i = 0; i < claim->value_size; i++)
    {
        printf("0x%x ", (uint8_t)claim->value[i]);
        if (SERVER_ENCLAVE_MRENCLAVE[i] != (uint8_t)claim->value[i])
        {
            printf(
                TLS_ENCLAVE "\nunique_id[%zu] expected: 0x%0x  found: 0x%0x ",
                i,
                SERVER_ENCLAVE_MRENCLAVE[i],
                (uint8_t)claim->value[i]);
            printf(TLS_ENCLAVE "failed: unique_id not equal\n");
            goto exit;
        }
    }
    printf("\n" TLS_ENCLAVE "unique_id validation passed\n");
    result = OE_OK;
exit:
    return result;
}
