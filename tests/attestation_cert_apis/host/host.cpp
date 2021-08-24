// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/attestation/relying_party.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common.h"
#include "tls_u.h"

#if defined(_WIN32)
#include <ShlObj.h>
#include <Windows.h>
#endif

#define SKIP_RETURN_CODE 2

#define FILENAME_LENGTH 80

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept an connection reqest
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    OE_TRACE_INFO(
        "identity.security_version = %d\n", identity->security_version);
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity.security_version check failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.  In a real scenario,
    // custom id checking should be done here
    OE_TRACE_INFO("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

oe_result_t test_attestation_certificate(
    oe_enclave_t* enclave,
    key_type_t key_type)
{
    oe_result_t result = OE_FAILURE;
    signed_certificate_t certificate = {0};

    OE_TRACE_INFO(
        "Host: get the attestation certificate signed with %s key from an "
        "enclave\n",
        key_type == KEY_TYPE_RSA ? "a RSA" : "an EC");
    OE_CHECK(
        get_attestation_certificate(enclave, &result, key_type, &certificate));
    OE_CHECK(result);

    // validate cert
    OE_TRACE_INFO("Host: Verifying the attestation certificate\n");
    OE_TRACE_INFO(
        "Host: cert = %p cert_size = %zu\n",
        certificate.data,
        certificate.size);
    result = oe_verify_attestation_certificate(
        certificate.data, certificate.size, enclave_identity_verifier, NULL);
    OE_TRACE_INFO(
        "Host: Verifying the certificate from the host ... %s\n",
        result == OE_OK ? "Success" : "Fail");

done:
    free(certificate.data);
    return result;
}

oe_result_t test_passport_certificate(
    oe_enclave_t* enclave,
    key_type_t key_type)
{
    oe_result_t result = OE_FAILURE;
    signed_certificate_t certificate = {0};
    uint8_t* output_attestation_result = nullptr;
    size_t output_attestation_result_size = 0;

    OE_TRACE_INFO(
        "Host: get the passport certificate signed with %s key from an enclave"
        "\n",
        key_type == KEY_TYPE_RSA ? "a RSA" : "an EC");
    OE_CHECK(
        get_passport_certificate(enclave, &result, key_type, &certificate));
    OE_CHECK(result);

    OE_TRACE_INFO("Host: Parsing the passport certificate\n");
    OE_TRACE_INFO(
        "Host: cert = %p cert_size = %zu\n",
        certificate.data,
        certificate.size);
    result = oe_parse_passport_attestation_certificate_v1(
        certificate.data,
        certificate.size,
        &output_attestation_result,
        &output_attestation_result_size);
    OE_TRACE_INFO(
        "Host: Parsing the certificate from the host ... %s\n",
        result == OE_OK ? "Success" : "Fail");
    OE_TEST(result == OE_OK);

    OE_TEST(output_attestation_result_size == sizeof(attestation_result));
    for (size_t i = 0; i < output_attestation_result_size; i++)
        OE_TEST(output_attestation_result[i] == attestation_result[i]);

done:
    free(certificate.data);
    free(output_attestation_result);
    return result;
}

oe_result_t test_background_check_certificate(
    oe_enclave_t* enclave,
    attestation_type_t attestation_type,
    key_type_t key_type)
{
    oe_result_t result = OE_FAILURE;
    signed_certificate_t certificate = {0};

    uint8_t* output_evidence = nullptr;
    size_t output_evidence_size = 0;
    uint8_t* output_inittime_claims = nullptr;
    size_t output_inittime_claims_size = 0;
    uint8_t* output_runtime_claims = nullptr;
    size_t output_runtime_claims_size = 0;

    OE_TRACE_INFO(
        "Host: get the background-check certificate signed with %s key from an "
        "enclave\n",
        key_type == KEY_TYPE_RSA ? "a RSA" : "an EC");
    OE_CHECK(get_background_check_certificate(
        enclave, &result, attestation_type, key_type, &certificate));
    OE_CHECK(result);

    OE_TRACE_INFO("Host: Parsing the background-check certificate\n");
    OE_TRACE_INFO(
        "Host: cert = %p cert_size = %zu\n",
        certificate.data,
        certificate.size);

    result = oe_parse_background_check_attestation_certificate_v1(
        certificate.data,
        certificate.size,
        &output_evidence,
        &output_evidence_size,
        &output_inittime_claims,
        &output_inittime_claims_size,
        &output_runtime_claims,
        &output_runtime_claims_size);
    OE_TRACE_INFO(
        "Host: Parsing the certificate from the host ... %s\n",
        result == OE_OK ? "Success" : "Fail");
    OE_TEST(result == OE_OK);

    OE_TEST(output_inittime_claims_size == sizeof(inittime_claims));
    for (size_t i = 0; i < output_inittime_claims_size; i++)
        OE_TEST(output_inittime_claims[i] == inittime_claims[i]);

    OE_TEST(output_runtime_claims_size == sizeof(runtime_claims));
    for (size_t i = 0; i < output_runtime_claims_size; i++)
        OE_TEST(output_runtime_claims[i] == runtime_claims[i]);

    if (attestation_type == ATTESTATION_TYPE_REMOTE)
    {
        OE_CHECK(oe_verifier_initialize());
        OE_CHECK(oe_verify_evidence(
            nullptr,
            output_evidence,
            output_evidence_size,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            nullptr));
        oe_verifier_shutdown();
    }

    result = OE_OK;

done:
    free(certificate.data);
    free(output_evidence);
    free(output_inittime_claims);
    free(output_runtime_claims);
    return result;
}

int main(int argc, const char* argv[])
{
    if (!oe_has_sgx_quote_provider())
    {
        // this test should not run on any platforms where DCAP libraries are
        // not found.
        OE_TRACE_INFO("=== tests skipped when DCAP libraries are not found.\n");
        return SKIP_RETURN_CODE;
    }

#ifdef _WIN32
    /* This is a workaround for running in Visual Studio 2017 Test Explorer
     * where the environment variables are not correctly propagated to the
     * test. This is resolved in Visual Studio 2019 */
    WCHAR path[_MAX_PATH];

    if (!GetEnvironmentVariableW(L"SystemRoot", path, _MAX_PATH))
    {
        if (GetLastError() != ERROR_ENVVAR_NOT_FOUND)
            exit(1);

        UINT path_length = GetSystemWindowsDirectoryW(path, _MAX_PATH);
        if (path_length == 0 || path_length > _MAX_PATH)
            exit(1);

        if (SetEnvironmentVariableW(L"SystemRoot", path) == 0)
            exit(1);
    }

    if (!GetEnvironmentVariableW(L"LOCALAPPDATA", path, _MAX_PATH))
    {
        if (GetLastError() != ERROR_ENVVAR_NOT_FOUND)
            exit(1);

        WCHAR* local_path = NULL;
        if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &local_path) !=
            S_OK)
        {
            exit(1);
        }

        BOOL success = SetEnvironmentVariableW(L"LOCALAPPDATA", local_path);
        CoTaskMemFree(local_path);

        if (!success)
            exit(1);
    }
#endif

    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        OE_TRACE_ERROR("Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    if ((result = oe_create_tls_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    OE_TEST(test_attestation_certificate(enclave, KEY_TYPE_EC) == OE_OK);
    OE_TEST(test_attestation_certificate(enclave, KEY_TYPE_RSA) == OE_OK);
    OE_TEST(test_passport_certificate(enclave, KEY_TYPE_EC) == OE_OK);
    OE_TEST(test_passport_certificate(enclave, KEY_TYPE_RSA) == OE_OK);
    OE_TEST(
        test_background_check_certificate(
            enclave, ATTESTATION_TYPE_LOCAL, KEY_TYPE_EC) == OE_OK);
    OE_TEST(
        test_background_check_certificate(
            enclave, ATTESTATION_TYPE_LOCAL, KEY_TYPE_RSA) == OE_OK);
    OE_TEST(
        test_background_check_certificate(
            enclave, ATTESTATION_TYPE_REMOTE, KEY_TYPE_EC) == OE_OK);
    OE_TEST(
        test_background_check_certificate(
            enclave, ATTESTATION_TYPE_REMOTE, KEY_TYPE_RSA) == OE_OK);

    // Negative tests
    OE_TEST(test_passport_certificate_negative(enclave, &result) == OE_OK);
    OE_TEST(result == OE_OK);
    OE_TEST(
        test_background_check_certificate_negative(enclave, &result) == OE_OK);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);
    printf("=== passed all tests (attestation_cert_apis)\n");
    return 0;
}
