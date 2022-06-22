// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "cert_verify_config.h"

/* On the server side, we can't verify claim. During the build process,
CLIENT_ENCLAVE_MRENCLAVE is not available as client image is built later.
We can only verify the claim value of server or client, but not both.
`verify_claim_value` always returns OE_OK so that it can work with common
code in identity_verifier.cpp */

oe_result_t verify_claim_value(const oe_claim_t* claim)
{
    oe_result_t result = OE_OK;
    printf("\nverify unique_id:\n");
    for (size_t i = 0; i < claim->value_size; i++)
        printf("0x%x ", (uint8_t)claim->value[i]);
    printf("\n");
    return result;
}
