// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>

//#include <openenclave/corelibc/stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_t.h"
#define UNREFERENCE(x) (void(x)) // Prevent unused warning

#define printf oe_host_printf

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    if (identity->security_version < 1)
    {
        printf(
            "identity->security_version checking failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // the unique ID for the enclave
    // For SGX enclaves, this is the MRENCLAVE value
    printf("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    }

    // The signer ID for the enclave.
    // For SGX enclaves, this is the MRSIGNER value
    printf("\nparsed_report->identity.signer_id :\n");
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

    result = OE_OK;
done:
    return result;
}

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

    OE_TRACE_INFO("Generate key pair");

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
    OE_CHECK(result);

    result = oe_get_private_key_by_policy(
        OE_SEAL_POLICY_UNIQUE,
        &params,
        private_key,
        private_key_size,
        NULL,
        NULL);
    OE_CHECK(result);

done:
    return result;
}

oe_result_t get_TLS_cert(unsigned char** cert, size_t* cert_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* host_cert_buf = NULL;

    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;

    uint8_t* private_key = NULL;
    size_t private_key_size = 0;
    uint8_t* public_key = NULL;
    size_t public_key_size = 0;

    printf("called into enclave\n");
    // fflush(stdout);

    // generate public/private key pair
    result = generate_key_pair(
        &public_key, &public_key_size, &private_key, &private_key_size);
    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    result = oe_gen_x509cert_for_TLS(
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &output_cert,
        &output_cert_size);
    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    OE_TRACE_INFO("output_cert_size = 0x%x", output_cert_size);
    // validate cert inside the enclave
    result = oe_verify_tls_cert(
        output_cert, output_cert_size, enclave_identity_verifier, NULL);
    printf(
        "\nFrom inside encalve: verifying SGX certificate extensions... %s\n",
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

    if (private_key)
        oe_free_key(private_key, private_key_size, NULL, 0);
    if (public_key)
        oe_free_key(public_key, public_key_size, NULL, 0);

    // free certificate buffer
    if (output_cert)
        oe_free(output_cert);

    return result;
}

void free_TLS_cert(unsigned char* cert, size_t cert_size)
{
    OE_TRACE_INFO(
        "test from tls enclave: cert = %p cert_size = 0x%x", cert, cert_size);
    oe_host_free(cert);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
