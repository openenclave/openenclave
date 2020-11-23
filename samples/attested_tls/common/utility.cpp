// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "utility.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/sgx/report.h>

// input: input_data and input_data_len
// output: key, key_size
oe_result_t generate_key_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    oe_result_t result = OE_FAILURE;
    oe_asymmetric_key_params_t params;
    char user_data[] = "test user data!";
    size_t user_data_size = sizeof(user_data) - 1;

    // Call oe_get_public_key_by_policy() to generate key pair derived from an
    // enclave's seal key If an enclave does not want to have this key pair tied
    // to enclave instance, it can generate its own key pair using any chosen
    // crypto API

    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1; // MBEDTLS_ECP_DP_SECP256R1
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = user_data;
    params.user_data_size = user_data_size;
    result = oe_get_public_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        public_key,
        public_key_size,
        NULL,
        NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    if (result != OE_OK)
    {
        printf(
            "oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
            oe_result_str(result));
        goto done;
    }

done:
    return result;
}

bool verify_signer_id(
    const char* siging_public_key_buf,
    size_t siging_public_key_buf_size,
    uint8_t* signer_id_buf,
    size_t signer_id_buf_size)
{
    printf("\nverify connecting client's identity\n");

    uint8_t signer[OE_SIGNER_ID_SIZE];
    size_t signer_size = sizeof(signer);
    if (oe_sgx_get_signer_id_from_public_key(
            siging_public_key_buf,
            siging_public_key_buf_size,
            signer,
            &signer_size) != OE_OK)
    {
        printf("oe_sgx_get_signer_id_from_public_key failed\n");
        return false;
    }
    if (memcmp(signer, signer_id_buf, signer_id_buf_size) != 0)
    {
        printf("mrsigner is not equal!\n");
        for (size_t i = 0; i < signer_id_buf_size; i++)
        {
            printf(
                "0x%x - 0x%x\n", (uint8_t)signer[i], (uint8_t)signer_id_buf[i]);
        }
        return false;
    }
    return true;
}

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
const oe_claim_t* find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}

oe_result_t load_oe_modules()
{
    oe_result_t result = OE_FAILURE;

    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        printf(
            "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        printf(
            "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
exit:
    return result;
}