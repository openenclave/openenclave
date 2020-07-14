// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_t.h"

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in identity information to decide whether to
// accept a connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

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

    OE_TRACE_INFO("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nparsed_report->identity.signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

// This is the claims validation callback. A TLS connecting party (client or
// server) can verify the passed in claims to decide whether to
// accept a connection request
oe_result_t sgx_enclave_claims_verifier(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("sgx_enclave_claims_verifier is called with claims:\n");

    for (size_t i = 0; i < claims_length; i++)
    {
        oe_claim_t* claim = &claims[i];
        if (strcmp(claim->name, OE_CLAIM_SECURITY_VERSION) == 0)
        {
            uint32_t security_version = *(uint32_t*)(claim->value);
            // Check the enclave's security version
            if (security_version < 1)
            {
                OE_TRACE_ERROR(
                    "identity->security_version checking failed (%d)\n",
                    security_version);
                goto done;
            }
        }
        // Dump an enclave's unique ID, signer ID and Product ID. They are
        // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves. In a real
        // scenario, custom id checking should be done here
        else if (
            strcmp(claim->name, OE_CLAIM_SIGNER_ID) == 0 ||
            strcmp(claim->name, OE_CLAIM_UNIQUE_ID) == 0 ||
            strcmp(claim->name, OE_CLAIM_PRODUCT_ID) == 0)
        {
            OE_TRACE_INFO("Enclave %s:\n", claim->name);
            for (size_t j = 0; j < claim->value_size; j++)
            {
                OE_TRACE_INFO("0x%0x ", claim->value[j]);
            }
        }
    }

    result = OE_OK;
done:
    return result;
}

// input: input_data and input_data_len
// output: key, key_size
oe_result_t generate_key_pair(
    int key_type,
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size)
{
    oe_result_t result = OE_FAILURE;
    oe_asymmetric_key_params_t params;
    char user_data[] = "test user data!";
    size_t user_data_size = sizeof(user_data) - 1;
    uint8_t* local_public_key = NULL;
    uint8_t* local_private_key = NULL;

    OE_TRACE_INFO("Generate key pair");

    if (key_type == MBEDTLS_PK_ECKEY)
    {
        params.type =
            OE_ASYMMETRIC_KEY_EC_SECP256P1; // MBEDTLS_ECP_DP_SECP256R1
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
        OE_CHECK(result);

        result = oe_get_private_key_by_policy(
            OE_SEAL_POLICY_UNIQUE,
            &params,
            private_key,
            private_key_size,
            NULL,
            NULL);
        OE_CHECK(result);
    }
    else if (key_type == MBEDTLS_PK_RSA)
    {
        int res = -1;
        mbedtls_ctr_drbg_context ctr_drbg_contex;
        mbedtls_entropy_context entropy_context;
        mbedtls_pk_context pk_context;
        size_t local_public_key_size = 512;
        size_t local_private_key_size = 2048;

        mbedtls_ctr_drbg_init(&ctr_drbg_contex);
        mbedtls_entropy_init(&entropy_context);
        mbedtls_pk_init(&pk_context);

        // Initialize entropy.
        res = mbedtls_ctr_drbg_seed(
            &ctr_drbg_contex, mbedtls_entropy_func, &entropy_context, NULL, 0);
        if (res != 0)
        {
            OE_TRACE_ERROR("mbedtls_ctr_drbg_seed failed.");
            goto clean_rsa;
        }

        // Initialize RSA context.
        res = mbedtls_pk_setup(
            &pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (res != 0)
        {
            OE_TRACE_ERROR("mbedtls_pk_setup failed (%d).", res);
            goto clean_rsa;
        }

        // Generate an ephemeral 2048-bit RSA key pair with
        // exponent 65537 for the enclave.
        res = mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk_context),
            mbedtls_ctr_drbg_random,
            &ctr_drbg_contex,
            2048,
            65537);
        if (res != 0)
        {
            OE_TRACE_ERROR("mbedtls_rsa_gen_key failed (%d)\n", res);
            goto clean_rsa;
        }

        /* Call again with the allocated memory. */
        local_public_key = (uint8_t*)malloc(local_public_key_size);
        if (local_public_key == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        memset((void*)local_public_key, 0, local_public_key_size);

        local_private_key = (uint8_t*)malloc(local_private_key_size);
        if (local_private_key == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);
        memset((void*)local_private_key, 0, local_private_key_size);

        // Write out the public/private key in PEM format for exchange with
        // other enclaves.
        res = mbedtls_pk_write_pubkey_pem(
            &pk_context, local_public_key, local_public_key_size);
        if (res != 0)
        {
            OE_TRACE_ERROR("mbedtls_pk_write_pubkey_pem failed (%d)\n", res);
            goto clean_rsa;
        }

        res = mbedtls_pk_write_key_pem(
            &pk_context, local_private_key, local_private_key_size);
        if (res != 0)
        {
            OE_TRACE_ERROR("mbedtls_pk_write_key_pem failed (%d)\n", res);
            goto clean_rsa;
        }

        *public_key = local_public_key;
        // plus one to make sure \0 at the end is counted
        *public_key_size = strlen((const char*)local_public_key) + 1;

        *private_key = local_private_key;
        *private_key_size = strlen((const char*)local_private_key) + 1;

        local_public_key = NULL;
        local_private_key = NULL;

        OE_TRACE_INFO("public_key_size\n[%d]\n", *public_key_size);
        OE_TRACE_INFO("public_key\n[%s]\n", *public_key);
        result = OE_OK;

    clean_rsa:
        mbedtls_pk_free(&pk_context);
        mbedtls_ctr_drbg_free(&ctr_drbg_contex);
        mbedtls_entropy_free(&entropy_context);
    }
    else
    {
        OE_TRACE_ERROR("Unsupported key type [%d]\n", key_type);
    }

done:
    if (local_public_key)
        free(local_public_key);
    if (local_private_key)
        free(local_private_key);

    return result;
}

oe_result_t get_tls_cert_signed_with_key(
    int key_type,
    unsigned char** cert,
    size_t* cert_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* host_cert_buf = NULL;

    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;

    uint8_t* private_key = NULL;
    size_t private_key_size = 0;
    uint8_t* public_key = NULL;
    size_t public_key_size = 0;

    OE_TRACE_INFO("called into enclave\n");

    // generate public/private key pair
    result = generate_key_pair(
        key_type,
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    OE_TRACE_INFO("private key:[%s]\n", private_key);
    OE_TRACE_INFO("public key:[%s]\n", public_key);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &output_cert,
        &output_cert_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    OE_TRACE_INFO("output_cert_size = 0x%x", output_cert_size);
    // validate cert inside the enclave
    result = oe_verify_attestation_certificate(
        output_cert, output_cert_size, enclave_identity_verifier, NULL);
    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying the certificate with "
        "oe_verify_attestation_certificate()... %s\n",
        result == OE_OK ? "Success" : "Fail");

    if (result != OE_OK)
    {
        goto done;
    }

    // validate cert with oe_verify_attestation_certificate_with_evidence() to
    // ensure that the added report verifier part of the function works well
    result = oe_verify_attestation_certificate_with_evidence(
        output_cert, output_cert_size, sgx_enclave_claims_verifier, NULL);
    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying the certificate with "
        "oe_verify_attestation_certificate_with_evidence()... %s\n",
        result == OE_OK ? "Success" : "Fail");

    // copy cert to host memory
    host_cert_buf = (uint8_t*)oe_host_malloc(output_cert_size);
    if (host_cert_buf == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    // copy to the host for host-side validation test
    memcpy(host_cert_buf, output_cert, output_cert_size);
    *cert_size = output_cert_size;
    *cert = host_cert_buf;
    OE_TRACE_INFO("*cert = %p", *cert);
    OE_TRACE_INFO("*cert_size = 0x%x", *cert_size);

done:

    free(private_key);
    free(public_key);
    oe_free_attestation_certificate(output_cert);

    return result;
}

oe_result_t get_tls_cert_signed_with_ec_key(
    unsigned char** cert,
    size_t* cert_size)
{
    return get_tls_cert_signed_with_key(MBEDTLS_PK_ECKEY, cert, cert_size);
}

oe_result_t get_tls_cert_signed_with_rsa_key(
    unsigned char** cert,
    size_t* cert_size)
{
    return get_tls_cert_signed_with_key(MBEDTLS_PK_RSA, cert, cert_size);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
