// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>

#include <fstream>
#include <streambuf>
#include <vector>
#include "../../../common/sgx/tcbinfo.h"
#include "tests_u.h"

typedef struct
{
    const char* file_name;
    oe_result_t expected_result;
} qe_identity_test_case_t;

#define SKIP_RETURN_CODE 2

std::vector<uint8_t> FileToBytes(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());

    if (bytes.empty())
    {
        printf("File %s not found\n", path);
        exit(1);
    }

    // Explicitly add null character so that the bytes can be printed out
    // safely as a string if needed.
    bytes.push_back('\0');
    return bytes;
}

void check_parsed_common_values(oe_parsed_qe_identity_info_t& parsed_info)
{
    oe_datetime_t expected_issue_date = {2018, 10, 18, 1, 26, 20};
    OE_TEST(
        oe_datetime_compare(&parsed_info.issue_date, &expected_issue_date) ==
        0);

    oe_datetime_t expected_next_update = {2018, 11, 17, 1, 26, 20};
    OE_TEST(
        oe_datetime_compare(&parsed_info.next_update, &expected_next_update) ==
        0);

    OE_TEST(parsed_info.miscselect == 0x00000000);
    OE_TEST(parsed_info.miscselect_mask == 0xFFFFFFFF);

    OE_TEST(parsed_info.attributes.flags == 0x00000000000000000000000000000011);
    OE_TEST(parsed_info.attributes.xfrm == 0x00000000000000000000000000000000);
    // OE_TEST(parsed_info.attributesMask   == 0xFFFFFFFF);

    OE_TEST(parsed_info.isvprodid == 1);

    uint8_t expected_mrsigner[32] = {
        0x8C, 0x4F, 0x57, 0x75, 0xD7, 0x96, 0x50, 0x3E, 0x96, 0x13, 0x7F,
        0x77, 0xC6, 0x8A, 0x82, 0x9A, 0x00, 0x56, 0xAC, 0x8D, 0xED, 0x70,
        0x14, 0x0B, 0x08, 0x1B, 0x09, 0x44, 0x90, 0xC5, 0x7B, 0xFF};
    OE_TEST(
        memcmp(
            parsed_info.mrsigner,
            expected_mrsigner,
            sizeof(expected_mrsigner)) == 0);

    const uint8_t expected_signature[] = {
        0x3a, 0xd9, 0xd2, 0x81, 0x15, 0x48, 0xac, 0x36, 0xb5, 0xd5, 0x64,
        0x8a, 0x74, 0xe3, 0x52, 0x37, 0x7e, 0xa6, 0x81, 0xc2, 0xd7, 0x80,
        0xb7, 0x5f, 0x57, 0x9b, 0xb5, 0x05, 0x89, 0x98, 0xc4, 0x87, 0xa1,
        0x3c, 0x6f, 0xbf, 0x27, 0xb5, 0xba, 0xe2, 0x3e, 0x77, 0xf7, 0xd5,
        0x56, 0x57, 0xfe, 0xfe, 0xf1, 0x10, 0xc3, 0x0a, 0xe9, 0x19, 0x72,
        0x02, 0x46, 0x29, 0x13, 0xa9, 0x63, 0xe6, 0x80, 0x2b};
    OE_TEST(
        memcmp(
            parsed_info.signature,
            expected_signature,
            sizeof(expected_signature)) == 0);
}

void check_parsed_v1_values(oe_parsed_qe_identity_info_t& parsed_info)
{
    OE_TEST(parsed_info.version == 1);
    OE_TEST(parsed_info.isvsvn == 1);
    check_parsed_common_values(parsed_info);
}

void check_parsed_v2_values(oe_parsed_qe_identity_info_t& parsed_info)
{
    OE_TEST(parsed_info.version == 2);
    OE_TEST(parsed_info.tcb_evaluation_data_number == 5);
    OE_TEST(parsed_info.isvsvn == 2);
    OE_TEST(parsed_info.tcb_level.isvsvn[0] == 2);

    oe_datetime_t expected_tcb_date = {2019, 5, 15, 1, 2, 3};
    OE_TEST(
        oe_datetime_compare(
            &parsed_info.tcb_level.tcb_date, &expected_tcb_date) == 0);

    OE_TEST(parsed_info.tcb_level.tcb_status.fields.up_to_date == 1);
    OE_TEST(parsed_info.tcb_level.advisory_ids_size == 0);

    check_parsed_common_values(parsed_info);
}

void run_qe_identity_test_cases(oe_enclave_t* enclave)
{
    // validate positive case
    std::vector<uint8_t> positive_qe_id_info =
        FileToBytes("./data/qe_identity_ok.json");
    oe_parsed_qe_identity_info_t parsed_info = {0};
    oe_result_t ecall_result = OE_FAILURE;

    memset(&parsed_info, 0, sizeof(parsed_info));

    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qe_id_info[0],
            NULL,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    check_parsed_v1_values(parsed_info);

    // validate negative case
    qe_identity_test_case_t test_cases[] = {
        {"./data/qe_identity_missing_qeidentity.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_version.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_issuedate.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_nextupdate.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_miscselect.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_miscselectmask.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_attributes.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_attributesmask.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_isvprodid.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_isvsvn.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data/qe_identity_missing_signature.json",
         OE_JSON_INFO_PARSE_ERROR}};

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
    {
        std::vector<uint8_t> qeIdInfo = FileToBytes(test_cases[i].file_name);
        oe_parsed_qe_identity_info_t parsed_info = {0};
        oe_result_t ecall_result = OE_FAILURE;
        printf("Testing file %s ", test_cases[i].file_name);
        OE_TEST(
            test_verify_qe_identity_info(
                enclave,
                &ecall_result,
                (const char*)&qeIdInfo[0],
                NULL,
                &parsed_info) == OE_OK);

        printf(
            "%s: ecall_result = %s   expected_result = %s\n",
            test_cases[i].file_name,
            oe_result_str(ecall_result),
            oe_result_str(test_cases[i].expected_result));
        OE_TEST(ecall_result == test_cases[i].expected_result);
        printf("passed\n");
    }
}

void run_parse_advisoryids_json_test()
{
    const uint8_t* advisoryids_test0 = (const uint8_t*)"\"advisoryId1\"";
    const uint8_t* advisoryids_test1 =
        (const uint8_t*)"\"advisoryId1\", \"advisoryId2\", \"advisoryId3\"";
    const uint8_t* id_array[3];
    size_t id_size_array[3];
    size_t num_ids = 0;

    OE_TEST(
        oe_parse_advisoryids_json(
            advisoryids_test0,
            strlen((const char*)advisoryids_test0),
            (const uint8_t**)&id_array,
            3,
            (size_t*)id_size_array,
            3,
            &num_ids) == OE_OK);
    OE_TEST(num_ids == 1);

    OE_TEST(
        oe_parse_advisoryids_json(
            advisoryids_test1,
            strlen((const char*)advisoryids_test1),
            (const uint8_t**)&id_array,
            3,
            (size_t*)id_size_array,
            3,
            &num_ids) == OE_OK);
    OE_TEST(num_ids == 3);

    OE_TEST(
        oe_parse_advisoryids_json(
            NULL,
            0,
            (const uint8_t**)&id_array,
            3,
            (size_t*)id_size_array,
            3,
            &num_ids) == OE_INVALID_PARAMETER);
}

void run_qe_identity_v2_test_cases(oe_enclave_t* enclave)
{
    // validate positive case
    std::vector<uint8_t> positive_qe_id_info =
        FileToBytes("./data_v2/qe_identity_ok.json");
    std::vector<uint8_t> positive_qve_id_info =
        FileToBytes("./data_v2/qve_identity_ok.json");
    std::vector<uint8_t> positive_qe_id_info_with_advisoryids =
        FileToBytes("./data_v2/qe_identity_with_advisoryids.json");

    const uint8_t* advisoryIDs[2] = {0};
    size_t advisoryIDs_length[2] = {0};
    const char* expectedAdvisoryIDs[2] = {"INTEL-SA-00079", "INTEL-SA-00076"};
    size_t num_advisory_ids = 0;

    oe_parsed_qe_identity_info_t parsed_info = {0};
    oe_qe_identity_info_tcb_level_t platform_tcb_level = {{0}};
    oe_result_t ecall_result = OE_FAILURE;

    // QE Identity V2 positive test
    platform_tcb_level.isvsvn[0] = 2;
    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qe_id_info[0],
            &platform_tcb_level,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    OE_TEST(parsed_info.id == QE_IDENTITY_ID_QE);
    check_parsed_v2_values(parsed_info);
    printf("\n\nQE Identity V2 positive test. PASSED.\n");

    // QE Identity V2 negative, OutOfDate
    platform_tcb_level.isvsvn[0] = 1;
    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qe_id_info[0],
            &platform_tcb_level,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_TCB_LEVEL_INVALID);
    OE_TEST(parsed_info.id == QE_IDENTITY_ID_QE);
    OE_TEST(parsed_info.tcb_level.tcb_status.fields.outofdate == 1);
    printf("\n\nQE Identity V2 positive test, OutOfDate. PASSED.\n");

    // QE Identity V2 positive with advisoryIDs
    platform_tcb_level.isvsvn[0] = 2;
    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qe_id_info_with_advisoryids[0],
            &platform_tcb_level,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    OE_TEST(parsed_info.id == QE_IDENTITY_ID_QE);
    OE_TEST(parsed_info.tcb_level.tcb_status.fields.up_to_date == 1);
    OE_TEST(parsed_info.tcb_level.advisory_ids_size > 0);
    OE_TEST(
        parsed_info.tcb_level.advisory_ids_offset <
        positive_qe_id_info_with_advisoryids.size());

    const char* ptr = (const char*)&positive_qe_id_info_with_advisoryids
        [parsed_info.tcb_level.advisory_ids_offset];
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
    printf("QE Identity V2 positive test, with advisoryIDs. PASSED\n");

    // QVE Identity V2 positive test
    platform_tcb_level.isvsvn[0] = 2;
    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qve_id_info[0],
            &platform_tcb_level,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    OE_TEST(parsed_info.id == QE_IDENTITY_ID_QVE);
    check_parsed_v2_values(parsed_info);
    printf("\n\nQVE Identity V2 positive test. PASSED.\n");

    // negative test without a valid platform_tcb_level
    OE_TEST(
        test_verify_qe_identity_info(
            enclave,
            &ecall_result,
            (const char*)&positive_qe_id_info[0],
            NULL,
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_INVALID_PARAMETER);
    printf("\n\nQE Identity V2 negative test with invalid platform_tcb_level. "
           "PASSED.\n");

    // validate negative case
    qe_identity_test_case_t test_cases[] = {
        {"./data_v2/qe_identity_missing_qeidentity.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_version.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_issuedate.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_nextupdate.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_miscselect.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_miscselectmask.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_attributes.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_attributesmask.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_isvprodid.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_isvsvn.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_signature.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_id.json", OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_mrsigner.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_tcb_date.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_tcb_eval_data_num.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_tcb_levels.json",
         OE_JSON_INFO_PARSE_ERROR},
        {"./data_v2/qe_identity_missing_tcb_status.json",
         OE_JSON_INFO_PARSE_ERROR}};

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
    {
        std::vector<uint8_t> qeIdInfo = FileToBytes(test_cases[i].file_name);
        oe_parsed_qe_identity_info_t parsed_info = {0};
        oe_result_t ecall_result = OE_FAILURE;
        printf("Testing file %s ", test_cases[i].file_name);
        OE_TEST(
            test_verify_qe_identity_info(
                enclave,
                &ecall_result,
                (const char*)&qeIdInfo[0],
                &platform_tcb_level,
                &parsed_info) == OE_OK);

        printf(
            "%s: ecall_result = %s   expected_result = %s\n",
            test_cases[i].file_name,
            oe_result_str(ecall_result),
            oe_result_str(test_cases[i].expected_result));
        OE_TEST(ecall_result == test_cases[i].expected_result);
        printf("passed\n");
    }
}
