// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_USE_OPENSSL
#include <openssl/evp.h>
#define OE_KEY_TYPE_EC EVP_PKEY_EC
#define OE_KEY_TYPE_RSA EVP_PKEY_RSA
#else
#include <mbedtls/pk.h>
#define OE_KEY_TYPE_EC MBEDTLS_PK_ECKEY
#define OE_KEY_TYPE_RSA MBEDTLS_PK_RSA
#endif

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/relying_party.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common.h"
#include "rsa.h"
#include "tls_t.h"

const unsigned char subject_name[] = "CN=Open Enclave SDK,O=OESDK TLS,C=US";

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

// This is the claims validation function. A TLS connecting party (client or
// server) can verify the passed in claims to decide whether to
// accept a connection request.
oe_result_t enclave_claims_verifier(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_claims_verifier is called with claims:\n");

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

    OE_TRACE_INFO("Generate key pair");

    if (key_type == OE_KEY_TYPE_EC)
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
            nullptr,
            nullptr);
        OE_CHECK(result);

        result = oe_get_private_key_by_policy(
            OE_SEAL_POLICY_UNIQUE,
            &params,
            private_key,
            private_key_size,
            nullptr,
            nullptr);
        OE_CHECK(result);
    }
    else if (key_type == OE_KEY_TYPE_RSA)
    {
        OE_CHECK(generate_rsa_pair(
            public_key, public_key_size, private_key, private_key_size));
    }
    else
    {
        OE_RAISE_MSG(OE_FAILURE, "Unsupported key type [%d]\n", key_type);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t get_attestation_certificate_signed_with_key(
    int key_type,
    signed_certificate_t* certificate)
{
    oe_result_t result = OE_FAILURE;

    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;

    uint8_t* private_key = nullptr;
    size_t private_key_size = 0;
    uint8_t* public_key = nullptr;
    size_t public_key_size = 0;

    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;

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
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &output_certificate,
        &output_certificate_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    OE_TRACE_INFO("output_certificate_size = 0x%x", output_certificate_size);
    // validate cert inside the enclave
    result = oe_verify_attestation_certificate(
        output_certificate,
        output_certificate_size,
        enclave_identity_verifier,
        nullptr);
    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying the certificate with "
        "oe_verify_attestation_certificate()... %s\n",
        result == OE_OK ? "Success" : "Fail");

    if (result != OE_OK)
    {
        goto done;
    }

    // validate cert with oe_verify_attestation_certificate_with_evidence_v2()
    // to ensure that the added report verifier part of the function works well
    result = oe_verify_attestation_certificate_with_evidence_v2(
        output_certificate,
        output_certificate_size,
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);

    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying the certificate with "
        "oe_verify_attestation_certificate_with_evidence_v2()... %s\n",
        oe_result_str(result));

    OE_CHECK(result);

    result = enclave_claims_verifier(claims, claims_length, nullptr);

    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying enclave claims with "
        "enclave_claims_verifier()... %s\n",
        oe_result_str(result));

    OE_CHECK(result);

    certificate->size = output_certificate_size;
    certificate->data = output_certificate;

done:
    free(private_key);
    free(public_key);
    oe_free_claims(claims, claims_length);

    return result;
}

oe_result_t get_passport_certificate_signed_with_key(
    int key_type,
    signed_certificate_t* certificate)
{
    oe_result_t result = OE_FAILURE;

    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;

    uint8_t* private_key = nullptr;
    size_t private_key_size = 0;
    uint8_t* public_key = nullptr;
    size_t public_key_size = 0;

    uint8_t* output_attestation_result = nullptr;
    size_t output_attestation_result_size = 0;

    OE_TRACE_INFO("called into enclave\n");

    // generate public/private key pair
    result = generate_key_pair(
        key_type,
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    OE_TRACE_INFO("private key:[%s]\n", private_key);
    OE_TRACE_INFO("public key:[%s]\n", public_key);

    result = oe_get_passport_attestation_certificate_v1(
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        attestation_result,
        sizeof(attestation_result),
        &output_certificate,
        &output_certificate_size);
    OE_CHECK_MSG(result, "failed with %s\n", oe_result_str(result));

    OE_TRACE_INFO("output_certificate_size = %zu", output_certificate_size);
    // validate cert inside the enclave
    result = oe_parse_passport_attestation_certificate_v1(
        output_certificate,
        output_certificate_size,
        &output_attestation_result,
        &output_attestation_result_size);
    OE_TRACE_INFO(
        "\nFrom inside enclave: parsing the certificate with "
        "oe_parse_passport_attestation_certificate_v1()... %s\n",
        result == OE_OK ? "Success" : "Fail");

    OE_TEST(output_attestation_result_size == sizeof(attestation_result));
    for (size_t i = 0; i < output_attestation_result_size; i++)
        OE_TEST(output_attestation_result[i] == attestation_result[i]);

    certificate->size = output_certificate_size;
    certificate->data = output_certificate;
    result = OE_OK;

done:
    free(private_key);
    free(public_key);
    free(output_attestation_result);
    if (result != OE_OK)
        free(output_certificate);

    return result;
}

oe_result_t test_passport_certificate_negative(void)
{
    oe_result_t result = OE_FAILURE;

    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;

    uint8_t* private_key = nullptr;
    size_t private_key_size = 0;
    uint8_t* public_key = nullptr;
    size_t public_key_size = 0;

    uint8_t* output_attestation_result = nullptr;
    size_t output_attestation_result_size = 0;

    // generate public/private key pair
    result = generate_key_pair(
        OE_KEY_TYPE_RSA,
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    // missing private_key
    result = oe_get_passport_attestation_certificate_v1(
        subject_name,
        nullptr,
        0,
        public_key,
        public_key_size,
        attestation_result,
        sizeof(attestation_result),
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing public_key
    result = oe_get_passport_attestation_certificate_v1(
        subject_name,
        private_key,
        private_key_size,
        nullptr,
        0,
        attestation_result,
        sizeof(attestation_result),
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing attestation_result
    result = oe_get_passport_attestation_certificate_v1(
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing output_certificate
    result = oe_get_passport_attestation_certificate_v1(
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        attestation_result,
        sizeof(attestation_result),
        nullptr,
        nullptr);
    OE_TEST(result == OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_passport_attestation_certificate_v1(
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        attestation_result,
        sizeof(attestation_result),
        &output_certificate,
        &output_certificate_size));

    // missing certificate
    result = oe_parse_passport_attestation_certificate_v1(
        nullptr,
        0,
        &output_attestation_result,
        &output_attestation_result_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing output_attestation_result
    result = oe_parse_passport_attestation_certificate_v1(
        output_certificate, output_certificate_size, nullptr, nullptr);
    OE_TEST(result == OE_INVALID_PARAMETER);

    result = OE_OK;

done:
    free(private_key);
    free(public_key);
    free(output_attestation_result);
    free(output_certificate);

    return result;
}

oe_result_t get_background_check_certificate_signed_with_key(
    attestation_type_t attestation_type,
    int key_type,
    signed_certificate_t* certificate)
{
    oe_result_t result = OE_FAILURE;

    oe_uuid_t format_id = {0};
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;

    uint8_t* private_key = nullptr;
    size_t private_key_size = 0;
    uint8_t* public_key = nullptr;
    size_t public_key_size = 0;

    uint8_t* output_evidence = nullptr;
    size_t output_evidence_size = 0;
    uint8_t* output_inittime_claims = nullptr;
    size_t output_inittime_claims_size = 0;
    uint8_t* output_runtime_claims = nullptr;
    size_t output_runtime_claims_size = 0;

    OE_TRACE_INFO("called into enclave\n");

    // generate public/private key pair
    result = generate_key_pair(
        key_type,
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    OE_TRACE_INFO("private key:[%s]\n", private_key);
    OE_TRACE_INFO("public key:[%s]\n", public_key);

    if (attestation_type == ATTESTATION_TYPE_LOCAL)
        format_id = (oe_uuid_t)OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION;
    else if (attestation_type == ATTESTATION_TYPE_REMOTE)
        format_id = (oe_uuid_t)OE_FORMAT_UUID_SGX_ECDSA;
    else
        OE_RAISE(OE_UNSUPPORTED);

    oe_attester_initialize();
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_CHECK_MSG(result, "failed with %s\n", oe_result_str(result));

    OE_TRACE_INFO("output_certificate_size = %zu", output_certificate_size);

    result = oe_parse_background_check_attestation_certificate_v1(
        output_certificate,
        output_certificate_size,
        &output_evidence,
        &output_evidence_size,
        &output_inittime_claims,
        &output_inittime_claims_size,
        &output_runtime_claims,
        &output_runtime_claims_size);
    OE_TRACE_INFO(
        "\nFrom inside enclave: parsing the certificate with "
        "oe_parse_background_check_attestation_certificate_v1()... %s\n",
        result == OE_OK ? "Success" : "Fail");

    oe_host_printf(
        "output inittime claims size: %zu, expected: %zu\n",
        output_inittime_claims_size,
        sizeof(inittime_claims));
    OE_TEST(output_inittime_claims_size == sizeof(inittime_claims));
    for (size_t i = 0; i < output_inittime_claims_size; i++)
        OE_TEST(output_inittime_claims[i] == inittime_claims[i]);

    OE_TEST(output_runtime_claims_size == sizeof(runtime_claims));
    for (size_t i = 0; i < output_runtime_claims_size; i++)
        OE_TEST(output_runtime_claims[i] == runtime_claims[i]);

    certificate->size = output_certificate_size;
    certificate->data = output_certificate;
    result = OE_OK;

done:
    oe_attester_shutdown();
    free(private_key);
    free(public_key);
    free(output_evidence);
    free(output_inittime_claims);
    free(output_runtime_claims);
    if (result != OE_OK)
        free(output_certificate);

    return result;
}

oe_result_t test_background_check_certificate_negative()
{
    oe_result_t result = OE_FAILURE;

    oe_uuid_t format_id = {0};
    uint8_t* output_certificate = nullptr;
    size_t output_certificate_size = 0;

    uint8_t* private_key = nullptr;
    size_t private_key_size = 0;
    uint8_t* public_key = nullptr;
    size_t public_key_size = 0;

    uint8_t* output_evidence = nullptr;
    size_t output_evidence_size = 0;
    uint8_t* output_inittime_claims = nullptr;
    size_t output_inittime_claims_size = 0;
    uint8_t* output_runtime_claims = nullptr;
    size_t output_runtime_claims_size = 0;

    // generate public/private key pair
    result = generate_key_pair(
        OE_KEY_TYPE_RSA,
        &public_key,
        &public_key_size,
        &private_key,
        &private_key_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    oe_attester_initialize();

    // Unsupported format_id
    format_id = (oe_uuid_t)OE_FORMAT_UUID_SGX_EPID_LINKABLE;
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_UNSUPPORTED);

    // Unsupported format_id
    format_id = (oe_uuid_t)OE_FORMAT_UUID_SGX_EPID_UNLINKABLE;
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_UNSUPPORTED);

    // Unsupported format_id
    format_id = (oe_uuid_t)OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA;
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_UNSUPPORTED);

    // Unsupported format_id
    format_id = (oe_uuid_t)OE_FORMAT_UUID_LEGACY_REPORT_REMOTE;
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_UNSUPPORTED);

    // format_id is null
    result = oe_get_background_check_attestation_certificate_v1(
        nullptr,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing private_key
    format_id = (oe_uuid_t)OE_FORMAT_UUID_SGX_ECDSA;
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        nullptr,
        0,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing public_key
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        nullptr,
        0,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing output_certificate
    result = oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        nullptr,
        nullptr);
    OE_TEST(result == OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_background_check_attestation_certificate_v1(
        &format_id,
        subject_name,
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        inittime_claims,
        sizeof(inittime_claims),
        runtime_claims,
        sizeof(runtime_claims),
        nullptr,
        0,
        &output_certificate,
        &output_certificate_size));

    // missing certificate
    result = oe_parse_background_check_attestation_certificate_v1(
        nullptr,
        0,
        &output_evidence,
        &output_evidence_size,
        &output_inittime_claims,
        &output_inittime_claims_size,
        &output_runtime_claims,
        &output_runtime_claims_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    // missing output_evidence
    result = oe_parse_background_check_attestation_certificate_v1(
        output_certificate,
        output_certificate_size,
        nullptr,
        nullptr,
        &output_inittime_claims,
        &output_inittime_claims_size,
        &output_runtime_claims,
        &output_runtime_claims_size);
    OE_TEST(result == OE_INVALID_PARAMETER);

    result = OE_OK;

done:
    oe_attester_shutdown();
    free(private_key);
    free(public_key);
    free(output_evidence);
    free(output_inittime_claims);
    free(output_runtime_claims);
    free(output_certificate);

    return result;
}

oe_result_t get_attestation_certificate(
    key_type_t key_type,
    signed_certificate_t* certificate)
{
    if (key_type == KEY_TYPE_EC)
        return get_attestation_certificate_signed_with_key(
            OE_KEY_TYPE_EC, certificate);
    else if (key_type == KEY_TYPE_RSA)
        return get_attestation_certificate_signed_with_key(
            OE_KEY_TYPE_RSA, certificate);
    else
        return OE_UNSUPPORTED;
}

oe_result_t get_passport_certificate(
    key_type_t key_type,
    signed_certificate_t* certificate)
{
    if (key_type == KEY_TYPE_EC)
        return get_passport_certificate_signed_with_key(
            OE_KEY_TYPE_EC, certificate);
    else if (key_type == KEY_TYPE_RSA)
        return get_passport_certificate_signed_with_key(
            OE_KEY_TYPE_RSA, certificate);
    else
        return OE_UNSUPPORTED;
}

oe_result_t get_background_check_certificate(
    attestation_type_t attestation_type,
    key_type_t key_type,
    signed_certificate_t* certificate)
{
    if (key_type == KEY_TYPE_EC)
        return get_background_check_certificate_signed_with_key(
            attestation_type, OE_KEY_TYPE_EC, certificate);
    else if (key_type == KEY_TYPE_RSA)
        return get_background_check_certificate_signed_with_key(
            attestation_type, OE_KEY_TYPE_RSA, certificate);
    else
        return OE_UNSUPPORTED;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
