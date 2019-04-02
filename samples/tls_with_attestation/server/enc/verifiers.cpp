// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string>

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg)
{
    (void)arg;
    printf(
        "enclave_identity_verifier_callback is called with parsed report:\n");

    // Check the enclave's security version
    printf("identity->security_version = %d\n", identity->security_version);
    // if (identity->security_version < 1)
    // {
    // }

    // the unique ID for the enclave
    // For SGX enclaves, this is the MRENCLAVE value
    printf("identity->unique_id(MRENCLAVE) :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->unique_id[i]);
    }

    // The signer ID for the enclave.
    // For SGX enclaves, this is the MRSIGNER value
    printf("\nidentity->signer_id(MRSIGNER) :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }

    // The Product ID for the enclave.
    // For SGX enclaves, this is the ISVPRODID value
    printf("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->product_id[i]);
    }
    return OE_OK;
}