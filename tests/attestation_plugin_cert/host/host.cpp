// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_u.h"

#if defined(_WIN32)
#include <ShlObj.h>
#include <Windows.h>
#endif

#define TEST_EC_KEY 0
#define TEST_RSA_KEY 1
#define SKIP_RETURN_CODE 2

#define FILENAME_LENGTH 80

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

void run_test(oe_enclave_t* enclave, int test_type)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ecall_result = OE_FAILURE;
    unsigned char* certificate = nullptr;
    size_t certificate_size = 0;
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;

    OE_TRACE_INFO(
        "Host: get tls certificate signed with %s key from an enclave \n",
        test_type == TEST_RSA_KEY ? "a RSA" : "an EC");
    if (test_type == TEST_EC_KEY)
    {
        result = get_tls_cert_signed_with_ec_key(
            enclave, &ecall_result, &certificate, &certificate_size);
    }
    else if (test_type == TEST_RSA_KEY)
    {
        result = get_tls_cert_signed_with_rsa_key(
            enclave, &ecall_result, &certificate, &certificate_size);
    }

    if ((result != OE_OK) || (ecall_result != OE_OK))
        oe_put_err(
            "get_tls_cert_signed_with_%s_key() failed: result=%u",
            test_type == TEST_RSA_KEY ? "rsa" : "ec",
            result);

    fflush(stdout);

    {
        // for testing purpose, output the whole cer in DER format
        char filename[FILENAME_LENGTH];
        FILE* file = nullptr;

        sprintf_s(
            filename,
            sizeof(filename),
            "./cert_%s.der",
            test_type == TEST_RSA_KEY ? "rsa" : "ec");
        OE_TRACE_INFO(
            "Host: Log quote embedded certificate to file: [%s]\n", filename);
#ifdef _WIN32
        fopen_s(&file, filename, "wb");
#else
        file = fopen(filename, "wb");
#endif
        fwrite(certificate, 1, certificate_size, file);
        fclose(file);
    }

    // validate certificate
    OE_TRACE_INFO("Host: Verifying tls certificate\n");
    OE_TRACE_INFO(
        "Host: certificate = %p certificate_size = %d\n",
        certificate,
        certificate_size);
    result = oe_verify_attestation_certificate_with_evidence_v2(
        certificate,
        certificate_size,
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);

    OE_TRACE_INFO(
        "Host: Verifying the certificate from a host ... %s\n",
        oe_result_str(result));

    OE_CHECK(result);

    result = enclave_claims_verifier(claims, claims_length, nullptr);

    OE_TRACE_INFO(
        "Host: Verifying the enclave claims from a host ... %s\n",
        oe_result_str(result));

    OE_CHECK(result);

    fflush(stdout);
    OE_TEST(result == OE_OK);

done:
    OE_TRACE_INFO("free certificate 0x%p\n", certificate);
    // oe_verifier_shutdown();
    free(certificate);
    oe_free_claims(claims, claims_length);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = nullptr;

    if (!oe_sgx_has_quote_provider())
    {
        // this test should not run on any platforms where DCAP libraries are
        // not found.
        OE_TRACE_INFO("=== tests skipped when DCAP libraries are not found.\n");
        return SKIP_RETURN_CODE;
    }

    if (argc != 2)
    {
        OE_TRACE_ERROR("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    if ((result = oe_create_tls_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, nullptr, 0, &enclave)) !=
        OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    oe_verifier_initialize();

    run_test(enclave, TEST_EC_KEY);
    run_test(enclave, TEST_RSA_KEY);

    oe_verifier_shutdown();
    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);
    OE_TRACE_INFO("=== passed all tests (tls)\n");
    return 0;
}
