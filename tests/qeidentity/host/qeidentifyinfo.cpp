// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#ifdef OE_USE_LIBSGX

#include <openenclave/host.h>
#include <openenclave/internal/aesm.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>

#include <fstream>
#include <streambuf>
#include <vector>
#include "../../../common/tcbinfo.h"
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

void check_parsed_value(oe_parsed_qe_identity_info_t& parsed_info)
{
    OE_TEST(parsed_info.version == 1);

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
    OE_TEST(parsed_info.isvsvn == 1);

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
            &parsed_info) == OE_OK);
    OE_TEST(ecall_result == OE_OK);
    check_parsed_value(parsed_info);

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
                &parsed_info) == OE_OK);

        printf(
            "ecall_result = %d   expected_result = %d\n",
            ecall_result,
            test_cases[i].expected_result);
        OE_TEST(ecall_result == test_cases[i].expected_result);
        printf("passed\n");
    }
}

#endif
