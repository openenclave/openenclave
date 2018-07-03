// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
#include "../../../host/quote.h"
#include "../common/args.h"

#define SKIP_RETURN_CODE 2

std::vector<uint8_t> FileToBytes(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    // Explicitly add null character so that the bytes can be printed out
    // safely as a string if needed.
    bytes.push_back('\0');
    return bytes;
}

bool CheckParsedString(
    const uint8_t* str,
    uint32_t length,
    const char* expectedStr)
{
    uint32_t expectedLength = (uint32_t)strlen(expectedStr);
    if ((length == expectedLength) && str &&
        (memcmp(str, expectedStr, length) == 0))
        return true;

    printf("%d : %d\n", length, expectedLength);
    printf("Unexpected parsed string value = %*.*s", length, length, str);
    return false;
}

oe_result_t ParseJson(oe_enclave_t* enclave, const char* path)
{
    std::vector<uint8_t> json = FileToBytes(path);
    ParseJsonArgs args = {&json[0], (uint32_t)json.size(), OE_FAILURE};
    OE_TEST(oe_call_enclave(enclave, "TestParseJson", &args) == OE_OK);
    return args.result;
}

void TestJsonParser(oe_enclave_t* enclave)
{
    const char* passfiles[] = {"./data/json/pass1.json",
                               // Json constructs that the parser expects
                               // the callbacks to validate:
                               //      string content
                               //      number parsing
                               "./data/json/pass2.json"};

    for (size_t i = 0; i < OE_COUNTOF(passfiles); ++i)
    {
        OE_TEST(ParseJson(enclave, passfiles[i]) == OE_OK);
    }

    const char* negfiles[] = {
        "./data/json/neg1.json",
        "./data/json/neg2.json",
        "./data/json/neg3.json",
        "./data/json/neg4.json",
        "./data/json/neg5.json",
        "./data/json/neg6.json",
        /* Json types not supported */
        "./data/json/neg7.json", // true
        "./data/json/neg6.json", // false
        "./data/json/neg6.json", // null
    };

    for (size_t i = 0; i < OE_COUNTOF(negfiles); ++i)
    {
        OE_TEST(ParseJson(enclave, negfiles[i]) == OE_FAILURE);
    }
}

void TestVerifyTCBInfo(oe_enclave_t* enclave)
{
    std::vector<uint8_t> tcbInfo = FileToBytes("./data/tcbInfo.json");
    oe_parsed_tcb_info_t parsedInfo = {0};
    VerifyTCBInfoArgs args = {
        &tcbInfo[0], (uint32_t)tcbInfo.size(), &parsedInfo};

    OE_TEST(
        oe_call_enclave(enclave, "TestVerifyTCBInfo", &args) == OE_OK &&
        args.result == OE_OK);

    OE_TEST(parsedInfo.version == 1);
    OE_TEST(
        CheckParsedString(
            parsedInfo.issue_date,
            parsedInfo.issue_date_size,
            "2018-06-06T10:12:17.085Z"));
    OE_TEST(
        CheckParsedString(
            parsedInfo.fmspc, parsedInfo.fmspc_size, "00906EA10000"));

    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[0] == 4);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[1] == 4);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[2] == 2);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[3] == 4);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[4] == 1);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[5] == 128);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[6] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[7] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[8] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[9] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[10] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[11] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[12] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[13] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[14] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.sgx_tcb_comp_svn[15] == 0);
    OE_TEST(parsedInfo.aggregated_uptodate_tcb.pce_svn == 5);
    OE_TEST(
        parsedInfo.aggregated_uptodate_tcb.status == OE_TCB_STATUS_UP_TO_DATE);

    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[0] == 2);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[1] == 2);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[2] == 2);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[3] == 4);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[4] == 1);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[5] == 128);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[6] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[7] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[8] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[9] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[10] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[11] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[12] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[13] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[14] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.sgx_tcb_comp_svn[15] == 0);
    OE_TEST(parsedInfo.aggregated_outofdate_tcb.pce_svn == 4);
    OE_TEST(
        parsedInfo.aggregated_outofdate_tcb.status ==
        OE_TCB_STATUS_OUT_OF_DATE);

    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[0] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[1] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[2] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[3] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[4] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[5] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[6] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[7] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[8] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[9] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[10] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[11] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[12] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[13] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[14] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.sgx_tcb_comp_svn[15] == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.pce_svn == 0);
    OE_TEST(parsedInfo.aggregated_revoked_tcb.status == OE_TCB_STATUS_REVOKED);

    OE_TEST(
        CheckParsedString(
            parsedInfo.signature,
            parsedInfo.signature_size,
            "62d181c4ba863213b825d1c0b66b92a3dbdb27b8ff7c7250cb2b2ab87a8f90d5e5"
            "a1416914369d8f82c56cd3d875caa54ae4b917caf4af7a93dec52067cbfd7b"));

    printf("TestVerifyTCBInfo: Positive Test passed\n");

    const char* negativeFiles[] = {
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
    };

    for (size_t i = 0; i < sizeof(negativeFiles) / sizeof(negativeFiles[0]);
         ++i)
    {
        std::vector<uint8_t> tcbInfo = FileToBytes(negativeFiles[i]);
        oe_parsed_tcb_info_t parsedInfo = {0};
        VerifyTCBInfoArgs args = {
            &tcbInfo[0], (uint32_t)tcbInfo.size(), &parsedInfo};
        OE_TEST(
            oe_call_enclave(enclave, "TestVerifyTCBInfo", &args) == OE_OK &&
            args.result == OE_FAILURE);
        printf("TestVerifyTCBInfo: Negative Test %lu passed\n", i);
    }
}
