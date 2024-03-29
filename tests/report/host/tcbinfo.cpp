// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>

#include <fstream>
#include <streambuf>
#include <vector>
#include "../../../common/sgx/tcbinfo.h"
#include "../../../host/sgx/quote.h"
#include "tests_u.h"

#define SKIP_RETURN_CODE 2

int FileToBytes(const char* path, std::vector<uint8_t>* out)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());

    if (bytes.empty())
    {
        printf("File %s not found\n", path);
        return -1;
    }

    // Explicitly add null character so that the bytes can be printed out
    // safely as a string if needed.
    bytes.push_back('\0');
    *out = bytes;
    return 0;
}

void AssertParsedValues(oe_parsed_tcb_info_t& parsed_info, uint32_t version)
{
    OE_TEST(parsed_info.version == version);

    oe_datetime_t expected_issue_date = {2018, 6, 6, 10, 12, 17};
    oe_datetime_t* parsed_issue_date =
        parsed_info.version == 3 ? &parsed_info.tcb_info_v3.issue_date
                                 : &parsed_info.tcb_info_v2.issue_date;

    OE_TEST(oe_datetime_compare(parsed_issue_date, &expected_issue_date) == 0);

    uint8_t expected_fm_spc[6] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};
    OE_TEST(
        memcmp(
            OE_TCB_INFO_GET(&parsed_info, fmspc),
            expected_fm_spc,
            sizeof(expected_fm_spc)) == 0);

    uint8_t expected_pce_id[2] = {0x00, 0x00};
    OE_TEST(
        memcmp(
            OE_TCB_INFO_GET(&parsed_info, pceid),
            expected_pce_id,
            sizeof(expected_pce_id)) == 0);

    const uint8_t expected_signature[] = {
        0x62, 0xd1, 0x81, 0xc4, 0xba, 0x86, 0x32, 0x13, 0xb8, 0x25, 0xd1,
        0xc0, 0xb6, 0x6b, 0x92, 0xa3, 0xdb, 0xdb, 0x27, 0xb8, 0xff, 0x7c,
        0x72, 0x50, 0xcb, 0x2b, 0x2a, 0xb8, 0x7a, 0x8f, 0x90, 0xd5, 0xe5,
        0xa1, 0x41, 0x69, 0x14, 0x36, 0x9d, 0x8f, 0x82, 0xc5, 0x6c, 0xd3,
        0xd8, 0x75, 0xca, 0xa5, 0x4a, 0xe4, 0xb9, 0x17, 0xca, 0xf4, 0xaf,
        0x7a, 0x93, 0xde, 0xc5, 0x20, 0x67, 0xcb, 0xfd, 0x7b};
    OE_TEST(
        memcmp(
            parsed_info.signature,
            expected_signature,
            sizeof(expected_signature)) == 0);

    if (parsed_info.version != 1)
    {
        oe_datetime_t* parsed_tcb_date =
            parsed_info.version == 3
                ? &parsed_info.tcb_info_v3.tcb_level.tcb_date
                : &parsed_info.tcb_info_v2.tcb_level.tcb_date;

        //"tcbDate":"2018-01-04T01:02:03Z",
        oe_datetime_t expected_tcb_date = {2018, 1, 4, 1, 2, 3};
        OE_TEST(oe_datetime_compare(parsed_tcb_date, &expected_tcb_date) == 0);
    }
}

void TestVerifyTCBInfo(
    oe_enclave_t* enclave,
    const char* test_filename,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_info,
    oe_result_t expected,
    uint32_t version)
{
    std::vector<uint8_t> tcbInfo;
    OE_TEST(FileToBytes(test_filename, &tcbInfo) == 0);

    oe_result_t ecall_result = OE_FAILURE;

    // Contains nextUpdate field.
    memset(parsed_info, 0, sizeof(oe_parsed_tcb_info_t));
    platform_tcb_level->status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;

    OE_TEST(
        test_verify_tcb_info(
            enclave,
            &ecall_result,
            (const char*)&tcbInfo[0],
            platform_tcb_level,
            parsed_info) == OE_OK);
    OE_TEST_CODE(ecall_result, expected);
    AssertParsedValues(*parsed_info, version);

    oe_datetime_t nextUpdate = {2019, 6, 6, 10, 12, 17};
    oe_datetime_t* parsed_next_date =
        parsed_info->version == 3 ? &parsed_info->tcb_info_v3.next_update
                                  : &parsed_info->tcb_info_v2.next_update;

    OE_TEST(oe_datetime_compare(parsed_next_date, &nextUpdate) == 0);
}

void TestVerifyTCBInfo(oe_enclave_t* enclave, const char* test_filename)
{
    const uint32_t version = 1;
    oe_tcb_info_tcb_level_t platform_tcb_level = {
        {4, 4, 2, 4, 1, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8};
    oe_parsed_tcb_info_t parsed_info = {0};

    // ./data/tcbInfo.json contains 4 tcb levels.
    // The first level with pce svn = 5 is up to date.
    // The second level with pce svn = 4 needs configuration.
    // The third level with pce svn = 3 is out of date.
    // The fourth level with pce svn = 2 is revoked.

    // Set platform pce svn to 8 and assert that
    // the determined status is up to date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 8;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_OK,
        version);
    OE_TEST(platform_tcb_level.status.fields.up_to_date == 1);
    printf("UptoDate TCB Level determination test passed.\n");

    // Set platform pce svn to 4 and assert that
    // the determined status is configuration needed.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 4;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(platform_tcb_level.status.fields.configuration_needed == 1);
    printf("ConfigurationNeeded TCB Level determination test passed.\n");

    // Set platform pce svn to 3 and assert that
    // the determined status is out of date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 3;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(platform_tcb_level.status.fields.outofdate == 1);
    printf("OutOfDate TCB Level determination test passed.\n");

    // Set platform pce svn to 2 and assert that
    // the determined status is revoked.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 2;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(platform_tcb_level.status.fields.revoked == 1);
    printf("Revoked TCB Level determination test passed.\n");

    // Set each of the fields to a value not listed in the json and
    // test that the determined status is OE_TCB_LEVEL_INVALID
    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
        platform_tcb_level.sgx_tcb_comp_svn[i] = 0;
        TestVerifyTCBInfo(
            enclave,
            test_filename,
            &platform_tcb_level,
            &parsed_info,
            OE_TCB_LEVEL_INVALID,
            version);
        OE_TEST(
            platform_tcb_level.status.AsUINT32 == OE_TCB_LEVEL_STATUS_UNKNOWN);
        platform_tcb_level.sgx_tcb_comp_svn[i] = 1;
    }
    printf("Unknown TCB Level determination test passed.\n");

    printf("TestVerifyTCBInfo: Positive Tests passed\n");
}

void TestVerifyTCBInfo_Negative(
    oe_enclave_t* enclave,
    const char* file_names[],
    size_t file_cnt)
{
    for (size_t i = 0; i < file_cnt; ++i)
    {
        std::vector<uint8_t> tcbInfo;
        OE_TEST(FileToBytes(file_names[i], &tcbInfo) == 0);

        oe_parsed_tcb_info_t parsed_info = {0};
        oe_tcb_info_tcb_level_t platform_tcb_level = {{0}};
        oe_result_t ecall_result = OE_FAILURE;
        OE_TEST(
            test_verify_tcb_info(
                enclave,
                &ecall_result,
                (const char*)&tcbInfo[0],
                &platform_tcb_level,
                &parsed_info) == OE_OK);
        OE_TEST(ecall_result == OE_JSON_INFO_PARSE_ERROR);
        printf("TestVerifyTCBInfo: Negative Test %s passed\n", file_names[i]);
    }
}

void TestVerifyTCBInfoV2(oe_enclave_t* enclave, const char* test_filename)
{
    const uint32_t version = 2;
    oe_tcb_info_tcb_level_t platform_tcb_level = {
        {4, 4, 2, 4, 1, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8};
    oe_parsed_tcb_info_t parsed_info = {0};

    printf("TCB Info Version 2 tests:\n");
    // ./data_v2/tcbInfo.json contains 7 tcb levels.
    // The first level with pce svn = 8 is up to date.
    // The second level with pce svn = 7 is SWHardeningNeeded.
    // The third level with pce svn = 6 is ConfigurationAndSWHardeningNeeded.
    // The fourth level with pce svn = 5 is OutOfDateConfigurationNeeded
    // The fifth level with pce svn = 4 needs configuration.
    // The sixth level with pce svn = 3 is out of date.
    // The seventh level with pce svn = 2 is revoked.

    // Set platform pce svn to 9 and assert that
    // the determined status is up to date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 9;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_OK,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_UP_TO_DATE);
    printf("UptoDate TCB V2 Level determination test passed.\n");

    // Set platform pce svn to 7 and assert that
    // the determined status is SWHardeningNeeded.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 7;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_OK,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_SW_HARDENING_NEEDED);
    printf("SWHardeningNeeded TCB V2 Level determination test passed.\n");

    // Set platform pce svn to 6 and assert that
    // the determined status is ConfigurationAndSWHardeningNeeded.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 6;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED);

    printf("ConfigurationAndSWHardeningNeeded TCB V2 Level determination test "
           "passed.\n");

    // Set platform pce svn to 5 and assert that
    // the determined status is out of date configuration needed.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 5;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED);
    printf("OutOfDateConfigurationNeeded TCB V2 Level determination test "
           "passed.\n");

    // Set platform pce svn to 4 and assert that
    // the determined status is configuration needed.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 4;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_CONFIGURATION_NEEDED);
    printf("ConfigurationNeeded TCB V2 Level determination test passed.\n");

    // Set platform pce svn to 3 and assert that
    // the determined status is out of date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 3;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_OUT_OF_DATE);
    printf("OutOfDate TCB V2 Level determination test passed.\n");

    // Set platform pce svn to 2 and assert that
    // the determined status is revoked.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 2;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_REVOKED);
    printf("Revoked TCB V2 Level determination test passed.\n");

    // Set each of the fields to a value not listed in the json and
    // test that the determined status is OE_TCB_LEVEL_INVALID
    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
        platform_tcb_level.sgx_tcb_comp_svn[i] = 0;
        TestVerifyTCBInfo(
            enclave,
            test_filename,
            &platform_tcb_level,
            &parsed_info,
            OE_TCB_LEVEL_INVALID,
            version);
        OE_TEST(
            oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
            OE_SGX_TCB_STATUS_INVALID);
        platform_tcb_level.sgx_tcb_comp_svn[i] = 2;
    }
    printf("Unknown TCB Level determination test passed.\n");

    printf("TestVerifyTCBInfo V2: Positive Tests passed\n");
}

void TestVerifyTCBInfoV3(oe_enclave_t* enclave, const char* test_filename)
{
    const uint32_t version = 3;
    oe_tcb_info_tcb_level_t platform_tcb_level = {
        {7, 9, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8};
    oe_parsed_tcb_info_t parsed_info = {0};

    printf("TCB Info Version 3 tests with %s\n", test_filename);
    // ./data_v3/tcbInfo_sgx.json contains 5 tcb levels.
    // The first level with pce svn = 8 is UpToDate.
    // The second level with pce svn = 7 is SWHardeningNeeded.
    // The third level with pce svn = 6 is ConfigurationAndSWHardeningNeeded.
    // The fourth level with pce svn = 5 is OutOfDateConfigurationNeeded
    // The fifth level with pce svn = 4 needs OutOfDate.

    // Set platform pce svn to 9 and assert that
    // the determined status is up to date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 9;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_OK,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_UP_TO_DATE);
    printf("UptoDate TCB V3 Level determination test passed.\n");

    // Set platform pce svn to 7 and assert that
    // the determined status is SWHardeningNeeded.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 7;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_OK,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_SW_HARDENING_NEEDED);
    printf("SWHardeningNeeded TCB V3 Level determination test passed.\n");

    // Set platform pce svn to 6 and assert that
    // the determined status is ConfigurationAndSWHardeningNeeded.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 6;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_CONFIGURATION_AND_SW_HARDENING_NEEDED);
    printf("ConfigurationAndSWHardeningNeeded TCB V3 Level determination test "
           "passed.\n");

    // Set platform pce svn to 5 and assert that
    // the determined status is out of date configuration needed.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 5;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_OUT_OF_DATE_CONFIGURATION_NEEDED);
    printf("OutOfDateConfigurationNeeded TCB V3 Level determination test "
           "passed.\n");

    // Set platform pce svn to 4 and assert that
    // the determined status is configuration needed.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 4;
    TestVerifyTCBInfo(
        enclave,
        test_filename,
        &platform_tcb_level,
        &parsed_info,
        OE_TCB_LEVEL_INVALID,
        version);
    OE_TEST(
        oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
        OE_SGX_TCB_STATUS_OUT_OF_DATE);
    printf("ConfigurationNeeded TCB V3 Level determination test passed.\n");

    // Set each of the fields to a value not listed in the json and
    // test that the determined status is OE_TCB_LEVEL_INVALID
    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
        platform_tcb_level.sgx_tcb_comp_svn[i] = 0;
        TestVerifyTCBInfo(
            enclave,
            test_filename,
            &platform_tcb_level,
            &parsed_info,
            OE_TCB_LEVEL_INVALID,
            version);
        OE_TEST(
            oe_tcb_level_status_to_sgx_tcb_status(platform_tcb_level.status) ==
            OE_SGX_TCB_STATUS_INVALID);
        platform_tcb_level.sgx_tcb_comp_svn[i] = 2;
    }
    printf("Unknown TCB Level determination test passed.\n");

    printf("TestVerifyTCBInfo V3: Positive Tests passed\n");
}

void TestVerifyTCBInfo_AdvisoryIDs(
    oe_enclave_t* enclave,
    const char* test_filename,
    uint32_t version)
{
    std::vector<uint8_t> tcbInfo;
    oe_result_t ecall_result = OE_FAILURE;
    OE_TEST(FileToBytes(test_filename, &tcbInfo) == 0);

    oe_tcb_info_tcb_level_t platform_tcb_level = {
        {4, 4, 2, 4, 1, 128, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}, 8};
    oe_parsed_tcb_info_t parsed_info = {0};

    // Set platform pce svn to 8 and assert that
    // the determined status is up to date.
    platform_tcb_level.status.AsUINT32 = OE_TCB_LEVEL_STATUS_UNKNOWN;
    platform_tcb_level.pce_svn = 9;

    // Contains nextUpdate field.
    memset(&parsed_info, 0, sizeof(parsed_info));

    OE_TEST(
        test_verify_tcb_info(
            enclave,
            &ecall_result,
            (const char*)&tcbInfo[0],
            &platform_tcb_level,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    OE_TEST(platform_tcb_level.status.fields.up_to_date == 1);

    AssertParsedValues(parsed_info, version);
    oe_datetime_t nextUpdate = {2019, 6, 6, 10, 12, 17};
    oe_datetime_t* parsed_next_date =
        parsed_info.version == 3 ? &parsed_info.tcb_info_v3.next_update
                                 : &parsed_info.tcb_info_v2.next_update;
    OE_TEST(oe_datetime_compare(parsed_next_date, &nextUpdate) == 0);

    if (version == 2)
    {
        OE_TEST(
            parsed_info.tcb_info_v2.tcb_level.status.fields.up_to_date == 1);
        OE_TEST(parsed_info.tcb_info_v2.tcb_level.advisory_ids_size > 0);
        OE_TEST(
            parsed_info.tcb_info_v2.tcb_level.advisory_ids_offset <
            tcbInfo.size());
    }

    const char* ptr = (const char*)&tcbInfo[parsed_info.tcb_info_v2.tcb_level
                                                .advisory_ids_offset];
    const uint8_t* advisoryIDs[2] = {0};
    size_t advisoryIDs_length[2] = {0};
    const char* expectedAdvisoryIDs[2] = {"INTEL-SA-00079", "INTEL-SA-00076"};
    size_t num_advisory_ids = 0;
    OE_TEST(
        oe_parse_advisoryids_json(
            (const uint8_t*)ptr,
            parsed_info.tcb_info_v2.tcb_level.advisory_ids_size,
            (const uint8_t**)&advisoryIDs,
            2,
            (size_t*)&advisoryIDs_length,
            2,
            &num_advisory_ids) == OE_OK);
    OE_TEST(num_advisory_ids == 2);
    for (int i = 0; i < 2; i++)
    {
        printf(
            "AdvisoryIDs[%d]: %.*s\n",
            i,
            (int)advisoryIDs_length[i],
            advisoryIDs[i]);
        OE_TEST(
            strncmp(
                (const char*)advisoryIDs[i],
                expectedAdvisoryIDs[i],
                advisoryIDs_length[i]) == 0);
    }
    printf("TestVerifyTCBInfo: Positive Tests %s passed\n", test_filename);
}