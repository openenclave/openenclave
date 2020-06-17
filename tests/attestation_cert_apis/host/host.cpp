// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
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

void run_test(oe_enclave_t* enclave, int test_type)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t ecall_result;
    unsigned char* cert = NULL;
    size_t cert_size = 0;

    OE_TRACE_INFO(
        "Host: get tls certificate signed with %s key from an enclave \n",
        test_type == TEST_RSA_KEY ? "a RSA" : "an EC");
    if (test_type == TEST_EC_KEY)
    {
        result = get_tls_cert_signed_with_ec_key(
            enclave, &ecall_result, &cert, &cert_size);
    }
    else if (test_type == TEST_RSA_KEY)
    {
        result = get_tls_cert_signed_with_rsa_key(
            enclave, &ecall_result, &cert, &cert_size);
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
        FILE* file = NULL;

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
        fwrite(cert, 1, cert_size, file);
        fclose(file);
    }

    // validate cert
    OE_TRACE_INFO("Host: Verifying tls certificate\n");
    OE_TRACE_INFO("Host: cert = %p cert_size = %d\n", cert, cert_size);
    result = oe_verify_attestation_certificate(
        cert, cert_size, enclave_identity_verifier, NULL);
    OE_TRACE_INFO(
        "Host: Verifying the certificate from a host ... %s\n",
        result == OE_OK ? "Success" : "Fail");
    fflush(stdout);
    OE_TEST(result == OE_OK);

    OE_TRACE_INFO("free cert 0xx%p\n", cert);
    free(cert);
}

int main(int argc, const char* argv[])
{
#ifdef OE_LINK_SGX_DCAP_QL

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

    run_test(enclave, TEST_EC_KEY);
    run_test(enclave, TEST_RSA_KEY);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);
    OE_TRACE_INFO("=== passed all tests (tls)\n");
    return 0;
#else
    // this test should not run on any platforms where HAS_QUOTE_PROVIDER is not
    // defined
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    OE_TRACE_INFO("=== tests skipped when built with HAS_QUOTE_PROVIDER=OFF\n");
    return SKIP_RETURN_CODE;
#endif
}
