// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <ctime>
#include <vector>
#include "../../../common/sgx/tcbinfo.h"
#include "../../../host/sgx/quote.h"
#include "../common/tests.h"
#include "tests_u.h"

#ifdef _WIN32
#include <Shlobj.h>
#include <Windows.h>
#endif

#define SKIP_RETURN_CODE 2

extern void TestVerifyTCBInfo(
    oe_enclave_t* enclave,
    const char* test_file_name);
extern int FileToBytes(const char* path, std::vector<uint8_t>* output);

void generate_and_save_report(oe_enclave_t* enclave)
{
#ifdef OE_LINK_SGX_DCAP_QL
    static uint8_t* report;
    size_t report_size;
    OE_TEST(
        oe_get_report(
            enclave,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            &report,
            &report_size) == OE_OK);

    FILE* file = fopen("./data/generated_report.bytes", "wb");
    fwrite(report, 1, report_size, file);
    fclose(file);
    oe_free_report(report);
#else
    OE_UNUSED(enclave);
#endif
}

int load_and_verify_report()
{
    std::vector<uint8_t> report;
    int ret = FileToBytes("./data/generated_report.bytes", &report);

    // File not found, so skip the verification.
    if (ret != 0)
    {
        printf("load_and_verify_report(): Couldn't find report. Skipping...\n");
        return SKIP_RETURN_CODE;
    }

    OE_TEST(
        oe_verify_report(NULL, &report[0], report.size() - 1, NULL) == OE_OK);

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    sgx_target_info_t target_info = {{0}};

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

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(report)\n");
        return SKIP_RETURN_CODE;
    }

    // Load and attest report without creating any enclaves.
    if (argc == 3 && strcmp(argv[2], "--attest-generated-report") == 0)
    {
        return load_and_verify_report();
    }

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    /* Create the enclave */
    if ((result = oe_create_tests_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_tests_enclave(): result=%u", result);
    }

    /*
     * Host API tests.
     */
    g_enclave = enclave;

#ifdef OE_LINK_SGX_DCAP_QL

    /* Initialize the target info */
    {
        if ((result = sgx_get_qetarget_info(&target_info)) != OE_OK)
        {
            oe_put_err("sgx_get_qetarget_info(): result=%u", result);
        }
    }

    test_local_report(&target_info);
    test_remote_report();
    test_parse_report_negative();
    test_local_verify_report();

    test_remote_verify_report();

    test_verify_report_with_collaterals();

    OE_TEST(test_iso8601_time(enclave) == OE_OK);
    OE_TEST(test_iso8601_time_negative(enclave) == OE_OK);

    /*
     * Enclave API tests.
     */
    OE_TEST(enclave_test_local_report(enclave, &target_info) == OE_OK);
    OE_TEST(enclave_test_remote_report(enclave) == OE_OK);

    OE_TEST(enclave_test_parse_report_negative(enclave) == OE_OK);

    OE_TEST(enclave_test_local_verify_report(enclave) == OE_OK);

    OE_TEST(enclave_test_remote_verify_report(enclave) == OE_OK);

    OE_TEST(enclave_test_verify_report_with_collaterals(enclave) == OE_OK);

    TestVerifyTCBInfo(enclave, "./data/tcbInfo.json");
    TestVerifyTCBInfo(enclave, "./data/tcbInfo_with_pceid.json");

    // Get current time and pass it to enclave.
    std::time_t t = std::time(0);
    std::tm* tm = std::gmtime(&t);

    // convert std::tm to oe_datetime_t
    oe_datetime_t now = {(uint32_t)tm->tm_year + 1900,
                         (uint32_t)tm->tm_mon + 1,
                         (uint32_t)tm->tm_mday,
                         (uint32_t)tm->tm_hour,
                         (uint32_t)tm->tm_min,
                         (uint32_t)tm->tm_sec};

    test_minimum_issue_date(enclave, now);

    generate_and_save_report(enclave);
#else
    test_local_report(&target_info);
    test_parse_report_negative();
    test_local_verify_report();

    OE_TEST(test_iso8601_time(enclave) == OE_OK);
    OE_TEST(test_iso8601_time_negative(enclave) == OE_OK);

    OE_TEST(enclave_test_local_report(enclave, &target_info) == OE_OK);
    OE_TEST(enclave_test_parse_report_negative(enclave) == OE_OK);
    OE_TEST(enclave_test_local_verify_report(enclave) == OE_OK);

    // Get current time and pass it to enclave.
    std::time_t t = std::time(0);
    std::tm* tm = std::gmtime(&t);

    // convert std::tm to oe_datetime_t
    oe_datetime_t now = {(uint32_t)tm->tm_year + 1900,
                         (uint32_t)tm->tm_mon + 1,
                         (uint32_t)tm->tm_mday,
                         (uint32_t)tm->tm_hour,
                         (uint32_t)tm->tm_min,
                         (uint32_t)tm->tm_sec};
    test_minimum_issue_date(enclave, now);

    generate_and_save_report(enclave);
#endif

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }
    return 0;
}
