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
    OE_TEST(
        oe_datetime_compare(&parsed_info.issue_date, &expected_issue_date) ==
        0);

    uint8_t expected_fm_spc[6] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};
    OE_TEST(
        memcmp(parsed_info.fmspc, expected_fm_spc, sizeof(expected_fm_spc)) ==
        0);

    uint8_t expected_pce_id[2] = {0x00, 0x00};
    OE_TEST(
        memcmp(parsed_info.pceid, expected_pce_id, sizeof(expected_pce_id)) ==
        0);

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

    if (version == 2)
    {
        //"tcbDate":"2018-01-04T01:02:03Z",
        oe_datetime_t expected_tcb_date = {2018, 1, 4, 1, 2, 3};
        OE_TEST(
            oe_datetime_compare(
                &parsed_info.tcb_level.tcb_date, &expected_tcb_date) == 0);
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
    OE_TEST(oe_datetime_compare(&parsed_info->next_update, &nextUpdate) == 0);
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

    const char* negative_files[] = {
        // In the following files, a property in corresponding level has been
        // capitalized. JSON is case sensitive and therefore schema validation
        // should fail.
        "./data/tcbInfoNegativePropertyMissingLevel0.json",
        "./data/tcbInfoNegativePropertyMissingLevel1.json",
        "./data/tcbInfoNegativePropertyMissingLevel2.json",
        "./data/tcbInfoNegativePropertyMissingLevel3.json",
        // In the following files, a property in corresponding level has wrong
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

    for (size_t i = 0; i < sizeof(negative_files) / sizeof(negative_files[0]);
         ++i)
    {
        std::vector<uint8_t> tcbInfo;
        OE_TEST(FileToBytes(negative_files[i], &tcbInfo) == 0);

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
        printf(
            "TestVerifyTCBInfo: Negative Test %s passed\n", negative_files[i]);
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
    OE_TEST(platform_tcb_level.status.fields.up_to_date == 1);
    printf("UptoDate TCB Level determination test passed.\n");

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
    OE_TEST(platform_tcb_level.status.fields.up_to_date == 1);
    OE_TEST(platform_tcb_level.status.fields.sw_hardening_needed == 1);
    printf("SWHardeningNeeded TCB Level determination test passed.\n");

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
    OE_TEST(platform_tcb_level.status.fields.configuration_needed == 1);
    OE_TEST(platform_tcb_level.status.fields.sw_hardening_needed == 1);
    printf("ConfigurationAndSWHardeningNeeded TCB Level determination test "
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
    OE_TEST(platform_tcb_level.status.fields.qe_identity_out_of_date == 1);
    OE_TEST(platform_tcb_level.status.fields.configuration_needed == 1);
    printf(
        "OutOfDateConfigurationNeeded TCB Level determination test passed.\n");

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
        platform_tcb_level.sgx_tcb_comp_svn[i] = 2;
    }
    printf("Unknown TCB Level determination test passed.\n");

    printf("TestVerifyTCBInfo V2: Positive Tests passed\n");

    const char* negative_files[] = {
        // In the following files, a property in corresponding level has been
        // capitalized. JSON is case sensitive and therefore schema validation
        // should fail.
        "./data_v2/tcbInfoNegativePropertyMissingLevel0.json",
        "./data_v2/tcbInfoNegativePropertyMissingLevel1.json",
        "./data_v2/tcbInfoNegativePropertyMissingLevel2.json",
        "./data_v2/tcbInfoNegativePropertyMissingLevel3.json",
        // In the following files, a property in corresponding level has wrong
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

    for (size_t i = 0; i < sizeof(negative_files) / sizeof(negative_files[0]);
         ++i)
    {
        std::vector<uint8_t> tcbInfo;
        OE_TEST(FileToBytes(negative_files[i], &tcbInfo) == 0);

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
        printf(
            "TestVerifyTCBInfoV2: Negative Test %s passed\n",
            negative_files[i]);
    }
}

void TestVerifyTCBInfoV2_AdvisoryIDs(
    oe_enclave_t* enclave,
    const char* test_filename)
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

    AssertParsedValues(parsed_info, 2);
    oe_datetime_t nextUpdate = {2019, 6, 6, 10, 12, 17};
    OE_TEST(oe_datetime_compare(&parsed_info.next_update, &nextUpdate) == 0);

    OE_TEST(parsed_info.tcb_level.status.fields.up_to_date == 1);
    OE_TEST(parsed_info.tcb_level.advisory_ids_size > 0);
    OE_TEST(parsed_info.tcb_level.advisory_ids_offset < tcbInfo.size());

    const char* ptr =
        (const char*)&tcbInfo[parsed_info.tcb_level.advisory_ids_offset];
    const uint8_t* advisoryIDs[2] = {0};
    size_t advisoryIDs_length[2] = {0};
    const char* expectedAdvisoryIDs[2] = {"INTEL-SA-00079", "INTEL-SA-00076"};
    size_t num_advisory_ids = 0;
    OE_TEST(
        oe_parse_advisoryids_json(
            (const uint8_t*)ptr,
            parsed_info.tcb_level.advisory_ids_size,
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
    printf("TCB Info V2 positive test, with advisoryIDs. PASSED\n");
}