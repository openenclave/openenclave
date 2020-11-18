// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_e2e_t.h"
#include "utility.h"

// clang-format on

extern struct tls_control_args g_control_config;

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
    // enclave's seal key. If an enclave does not want to have this key pair
    // tied to enclave instance, it can generate its own key pair using any
    // chosen crypto API

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
    OE_CHECK_MSG(
        result,
        "oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));

    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    OE_CHECK_MSG(
        result,
        "oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE) = %s",
        oe_result_str(result));

done:
    return result;
}

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection request
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;

    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");
    if (g_control_config.fail_enclave_identity_verifier_callback)
        goto done;

    // Check the enclave's security version
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity->security_version checking failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves. In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("\nidentity->unique_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->unique_id[i]);

    OE_TRACE_INFO("\nparsed_report->identity.signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    // On a real enclave product, this is the place to check again the enclave
    // signing key by calling function like verify_mrsigner below. However, we
    // are not siging test cases, so this checking will be skipped.
    // tls_between_enclaves sample will have code show how to dothis checking if
    // (!verify_mrsigner((char *)OTHER_ENCLAVE_PUBLIC_KEY,
    //                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
    //                     identity->signer_id,
    //                     sizeof(identity->signer_id)))
    // {
    //     OE_TRACE_ERROR("failed:mrsigner not equal!\n");
    //     goto done;
    // }

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

oe_result_t load_oe_modules()
{
    oe_result_t result = OE_FAILURE;

    // Explicitly enabling features
    if ((result = oe_load_module_host_resolver()) != OE_OK)
    {
        OE_TRACE_ERROR(
            "oe_load_module_host_resolver failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
    if ((result = oe_load_module_host_socket_interface()) != OE_OK)
    {
        OE_TRACE_ERROR(
            "oe_load_module_host_socket_interface failed with %s\n",
            oe_result_str(result));
        goto exit;
    }
exit:
    return result;
}
