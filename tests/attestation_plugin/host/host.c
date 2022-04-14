// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <ShlObj.h>
#include <Windows.h>
#endif

#include "../../../host/sgx/quote.h"
#include "../plugin/tests.h"
#include "plugin_u.h"

#define SKIP_RETURN_CODE 2

void host_verify(
    const oe_uuid_t* format_id,
    bool wrapped_with_header,
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsements,
    size_t endorsements_size)
{
    printf("====== running host_verify.\n");
    verify_sgx_evidence(
        format_id,
        wrapped_with_header,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        endorsements,
        endorsements_size,
        test_claims,
        TEST_CLAIMS_SIZE);
}

#define DATAFILE_LICENSE_HEADER_SIZE 81
oe_result_t read_file_to_buffer(
    uint8_t** buffer,
    size_t* buffer_size,
    const char* filename)
{
    if (!filename || !buffer)
        return OE_INVALID_PARAMETER;

    void* data = NULL;
    size_t data_size = 0;
    FILE* fp = NULL;

#ifdef _WIN32
    OE_TEST(fopen_s(&fp, filename, "rb") == 0);
#else
    fp = fopen(filename, "rb");
#endif
    if (!fp)
        return OE_FAILURE;

    // find data size
    OE_TEST(fseek(fp, 0, SEEK_END) == 0);
    data_size = (size_t)ftell(fp) - DATAFILE_LICENSE_HEADER_SIZE;
    data = malloc(data_size);
    if (!data)
        return OE_OUT_OF_MEMORY;

    // Move file pointer after license
    OE_TEST(fseek(fp, DATAFILE_LICENSE_HEADER_SIZE, SEEK_SET) == 0);

#ifdef _WIN32
    OE_TEST(fread_s(data, data_size, 1, data_size, fp) == data_size);
#else
    OE_TEST(fread(data, 1, data_size, fp) == data_size);
#endif

    *buffer = (uint8_t*)data;
    *buffer_size = data_size;
    fclose(fp);
    return OE_OK;
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
    else
    {
        // set up mocks for tests
        set_up_mocks_for_host();
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
        if (SHGetKnownFolderPath(
                &FOLDERID_LocalAppData, 0, NULL, &local_path) != S_OK)
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

    if (argc != 4)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE {abspath-to-evidence} "
            "{abspath-to-endorsements}\n",
            argv[0]);
        exit(1);
    }

    // Skip in simulation mode.
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    // Register the host verifier.
    register_verifier();

    // Run all enclave tests.
    result = oe_create_plugin_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    /*
     * To test sgx pccs lib v3.0 and v3.1, we read evidence and endorsements
     * from file.
     * This test can be removed when the testing pipelines are updated
     * to use the latest sgx pccs lib.
     */

    size_t evidence_size, endorsements_size;
    uint8_t* evidence = NULL;
    uint8_t* endorsements = NULL;

    OE_TEST(read_file_to_buffer(&evidence, &evidence_size, argv[2]) == OE_OK);
    OE_TEST(
        read_file_to_buffer(&endorsements, &endorsements_size, argv[3]) ==
        OE_OK);

    OE_TEST_CODE(
        test_pck_crl_validation(
            enclave,
            (const uint8_t*)evidence,
            evidence_size,
            (const uint8_t*)endorsements,
            endorsements_size),
        OE_OK);

    OE_TEST_CODE(run_runtime_test(enclave), OE_OK);
    OE_TEST_CODE(register_sgx(enclave), OE_OK);
    OE_TEST_CODE(test_sgx(enclave), OE_OK);
    OE_TEST_CODE(unregister_sgx(enclave), OE_OK);
    OE_TEST_CODE(oe_terminate_enclave(enclave), OE_OK);

    // Run runtime test on the host.
    test_runtime();

    // Unregister verifier.
    unregister_verifier();

    if (endorsements)
        free(endorsements);
    if (evidence)
        free(evidence);

    return 0;
}
