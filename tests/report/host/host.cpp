// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/sgx/tests.h>
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

#ifdef _WIN32

#include <windows.h>

#define TRY_TO_USE_SGX_DCAP_QVL() \
    (GetEnvironmentVariableA("USE_SGX_QVL", NULL, 0) != 0)

#else

#define TRY_TO_USE_SGX_DCAP_QVL() (getenv("USE_SGX_QVL") != NULL)

#endif

extern void TestVerifyTCBInfo(
    oe_enclave_t* enclave,
    const char* test_file_name);
extern void TestVerifyTCBInfo_Negative(
    oe_enclave_t* enclave,
    const char* file_names[],
    size_t file_cnt);
extern void TestVerifyTCBInfoV2(
    oe_enclave_t* enclave,
    const char* test_filename);
extern void TestVerifyTCBInfo_AdvisoryIDs(
    oe_enclave_t* enclave,
    const char* test_filename,
    uint32_t version);
extern int FileToBytes(const char* path, std::vector<uint8_t>* output);

void generate_and_save_report(oe_enclave_t* enclave)
{
    if (!oe_has_sgx_quote_provider())
        return;

    static uint8_t* report;
    size_t report_size;
    OE_TEST_CODE(
        oe_get_report(
            enclave,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            &report,
            &report_size),
        OE_OK);
    FILE* file;
#ifdef _WIN32
    fopen_s(&file, "./data/generated_report.bytes", "wb");
#else
    file = fopen("./data/generated_report.bytes", "wb");
#endif
    fwrite(report, 1, report_size, file);
    fclose(file);
    oe_free_report(report);
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

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
    {
        uint8_t* report_buffer = nullptr;
        size_t report_buffer_size = 0;
        OE_TEST(
            oe_get_report(
                enclave, 0, nullptr, 0, &report_buffer, &report_buffer_size) ==
            OE_UNSUPPORTED);
    }
    else if (oe_has_sgx_quote_provider())
    {
        static oe_uuid_t sgx_ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

        /* Initialize the target info */
        {
            if ((result = sgx_get_qetarget_info(
                     &sgx_ecdsa_uuid, NULL, 0, &target_info)) != OE_OK)
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
        OE_TEST_CODE(enclave_test_local_report(enclave, &target_info), OE_OK);
        OE_TEST_CODE(enclave_test_remote_report(enclave), OE_OK);

        OE_TEST_CODE(enclave_test_parse_report_negative(enclave), OE_OK);

        OE_TEST_CODE(enclave_test_local_verify_report(enclave), OE_OK);

        OE_TEST_CODE(enclave_test_remote_verify_report(enclave), OE_OK);

        OE_TEST_CODE(
            enclave_test_verify_report_with_collaterals(enclave), OE_OK);

        TestVerifyTCBInfo(enclave, "./data/tcbInfo.json");
        TestVerifyTCBInfo(enclave, "./data/tcbInfo_with_pceid.json");
        const char* negative_files[] = {
            // In the following files, a property in corresponding level has
            // been
            // capitalized. JSON is case sensitive and therefore schema
            // validation
            // should fail.
            "./data/tcbInfoNegativePropertyMissingLevel0.json",
            "./data/tcbInfoNegativePropertyMissingLevel1.json",
            "./data/tcbInfoNegativePropertyMissingLevel2.json",
            "./data/tcbInfoNegativePropertyMissingLevel3.json",
            // In the following files, a property in corresponding level has
            // wrong
            // type.
            "./data/tcbInfoNegativePropertyWrongTypeLevel0.json",
            "./data/tcbInfoNegativePropertyWrongTypeLevel1.json",
            "./data/tcbInfoNegativePropertyWrongTypeLevel2.json",
            "./data/tcbInfoNegativePropertyWrongTypeLevel3.json",

            // Comp Svn greater than uint8_t
            "./data/tcbInfoNegativeCompSvn.json",

            // pce Svn greater than uint16_t
            "./data/tcbInfoNegativePceSvn.json",

            // Invalid issueDate field.
            "./data/tcbInfoNegativeInvalidIssueDate.json",

            // Invalid nextUpdate field.
            "./data/tcbInfoNegativeInvalidNextUpdate.json",

            // Missing nextUpdate field.
            "./data/tcbInfoNegativeMissingNextUpdate.json",

            // Signature != 64 bytes
            "./data/tcbInfoNegativeSignature.json",

            // Unsupported JSON constructs
            "./data/tcbInfoNegativeStringEscape.json",
            "./data/tcbInfoNegativeIntegerOverflow.json",
            "./data/tcbInfoNegativeIntegerWithSign.json",
            "./data/tcbInfoNegativeFloat.json",
        };
        TestVerifyTCBInfo_Negative(
            enclave, negative_files, OE_COUNTOF(negative_files));

        TestVerifyTCBInfoV2(enclave, "./data_v2/tcbInfo.json");
        TestVerifyTCBInfoV2(enclave, "./data_v2/tcbInfo_with_pceid.json");
        TestVerifyTCBInfo_AdvisoryIDs(
            enclave, "./data_v2/tcbInfoAdvisoryIds.json", 2);
        const char* negative_files_v2[] = {
            // In the following files, a property in corresponding level has
            // been
            // capitalized. JSON is case sensitive and therefore schema
            // validation
            // should fail.
            "./data_v2/tcbInfoNegativePropertyMissingLevel0.json",
            "./data_v2/tcbInfoNegativePropertyMissingLevel1.json",
            "./data_v2/tcbInfoNegativePropertyMissingLevel2.json",
            "./data_v2/tcbInfoNegativePropertyMissingLevel3.json",
            // In the following files, a property in corresponding level has
            // wrong
            // type.
            "./data_v2/tcbInfoNegativePropertyWrongTypeLevel0.json",
            "./data_v2/tcbInfoNegativePropertyWrongTypeLevel1.json",
            "./data_v2/tcbInfoNegativePropertyWrongTypeLevel2.json",
            "./data_v2/tcbInfoNegativePropertyWrongTypeLevel3.json",

            // Comp Svn greater than uint8_t
            "./data_v2/tcbInfoNegativeCompSvn.json",

            // pce Svn greater than uint16_t
            "./data_v2/tcbInfoNegativePceSvn.json",

            // Invalid issueDate field.
            "./data_v2/tcbInfoNegativeInvalidIssueDate.json",

            // Invalid nextUpdate field.
            "./data_v2/tcbInfoNegativeInvalidNextUpdate.json",

            // Missing nextUpdate field.
            "./data_v2/tcbInfoNegativeMissingNextUpdate.json",

            // Signature != 64 bytes
            "./data_v2/tcbInfoNegativeSignature.json",

            // Unsupported JSON constructs
            "./data_v2/tcbInfoNegativeStringEscape.json",
            "./data_v2/tcbInfoNegativeIntegerOverflow.json",
            "./data_v2/tcbInfoNegativeIntegerWithSign.json",
            "./data_v2/tcbInfoNegativeFloat.json",
            // TcbType != 0.
            "./data_v2/tcbInfoNegativeTcbType.json",
        };
        TestVerifyTCBInfo_Negative(
            enclave, negative_files_v2, OE_COUNTOF(negative_files_v2));
        {
            // _sgx_minimim_crl_tcb_issue_date cannot be used in DCAP QVL
            // Disable below test when using QVL
            if (!TRY_TO_USE_SGX_DCAP_QVL())
            {
                // Get current time and pass it to enclave.
                std::time_t t = std::time(0);
                std::tm tm;
                gmtime_r(&t, &tm);

                // convert std::tm to oe_datetime_t
                oe_datetime_t now = {
                    (uint32_t)tm.tm_year + 1900,
                    (uint32_t)tm.tm_mon + 1,
                    (uint32_t)tm.tm_mday,
                    (uint32_t)tm.tm_hour,
                    (uint32_t)tm.tm_min,
                    (uint32_t)tm.tm_sec};
                test_minimum_issue_date(enclave, now);
            }
        }

        generate_and_save_report(enclave);
    }
    else
    {
        test_local_report(&target_info);
        test_parse_report_negative();
        test_local_verify_report();

        OE_TEST(test_iso8601_time(enclave) == OE_OK);
        OE_TEST(test_iso8601_time_negative(enclave) == OE_OK);

        OE_TEST(enclave_test_local_report(enclave, &target_info) == OE_OK);
        OE_TEST(enclave_test_parse_report_negative(enclave) == OE_OK);
        OE_TEST(enclave_test_local_verify_report(enclave) == OE_OK);
    }

    test_get_signer_id_from_public_key();
    OE_TEST(enclave_test_get_signer_id_from_public_key(enclave) == OE_OK);

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }
    return 0;
}
