// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string>
#include "../../common/tls_client_enc_pubkey.h"
#include "../../common/utility.h"

oe_result_t enclave_claims_verifier_callback(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg)
{
    OE_UNUSED(arg);

    oe_result_t result = OE_VERIFY_FAILED;
    const oe_claim_t* claim;

    printf(TLS_SERVER
           "enclave_claims_verifier_callback is called with enclave "
           "identity information extracted from the evidence claims:\n");

    // Enclave's security version
    if ((claim = find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == nullptr)
    {
        printf(TLS_SERVER "could not find OE_CLAIM_SECURITY_VERSION\n");
        goto exit;
    }
    if (claim->value_size != sizeof(uint32_t))
    {
        printf(
            "security_version size(%lu) checking failed\n", claim->value_size);
        goto exit;
    }
    printf(TLS_SERVER "\nsecurity_version = %d\n", *claim->value);

    // The unique ID for the enclave, for SGX enclaves, this is client's
    // MRENCLAVE
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID)) ==
        nullptr)
    {
        printf(TLS_SERVER "could not find OE_CLAIM_UNIQUE_ID\n");
        goto exit;
    }
    if (claim->value_size != OE_UNIQUE_ID_SIZE)
    {
        printf(
            TLS_SERVER "unique_id size(%lu) checking failed\n",
            claim->value_size);
        goto exit;
    }
    printf(TLS_CLIENT "\nunique_id:\n");
    for (int i = 0; i < claim->value_size; i++)
        printf("0x%0x ", (uint8_t)claim->value[i]);
    printf("\n");

    // The signer ID for the enclave, for SGX enclaves, this is the MRSIGNER
    // value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        nullptr)
    {
        printf(TLS_SERVER "could not find OE_CLAIM_SIGNER_ID\n");
        goto exit;
    }
    if (claim->value_size != OE_SIGNER_ID_SIZE)
    {
        printf(
            TLS_SERVER "signer_id size(%lu) checking failed\n",
            claim->value_size);
        goto exit;
    }
    printf(TLS_SERVER "\nverify signer_id:\n");
    for (int i = 0; i < claim->value_size; i++)
        printf("0x%0x ", (uint8_t)claim->value[i]);

    if (!verify_signer_id(
            (char*)OTHER_ENCLAVE_PUBLIC_KEY,
            sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
            claim->value,
            claim->value_size))
    {
        printf(TLS_SERVER "failed: signer_id not equal\n");
        goto exit;
    }
    printf(TLS_SERVER "signer_id validation passed\n");

    // The product ID for the enclave, for SGX enclaves, this is the ISVPRODID
    // value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr)
    {
        printf(TLS_SERVER "could not find OE_CLAIM_PRODUCT_ID\n");
        goto exit;
    }
    if (claim->value_size != OE_PRODUCT_ID_SIZE)
    {
        printf(
            TLS_SERVER "product_id size(%lu) checking failed\n",
            claim->value_size);
        goto exit;
    }
    printf(TLS_SERVER "\nproduct_id:\n");
    for (int i = 0; i < claim->value_size; i++)
        printf("0x%0x ", (uint8_t)claim->value[i]);
    printf("\n\n");

    result = OE_OK;

exit:

    return result;
}
