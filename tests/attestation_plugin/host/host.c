// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

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

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
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

    run_runtime_test(enclave);
    register_sgx(enclave);
    test_sgx(enclave);
    unregister_sgx(enclave);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    // Run runtime test on the host.
    test_runtime();

    // Unregister verifier.
    unregister_verifier();
    return 0;
}
