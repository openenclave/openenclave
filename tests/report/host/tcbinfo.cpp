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
    const char* passFiles[] = {"./data/json/pass.json",
                               "./data/json/passnumber.json",
                               // Test set of strings allowed by the parser.
                               // JSON strings must be double quoted. The parser
                               // validates the escape sequences, but does not
                               // unescape them.
                               "./data/json/passstring.json"};

    for (size_t i = 0; i < OE_COUNTOF(passFiles); ++i)
    {
        OE_TEST(ParseJson(enclave, passFiles[i]) == OE_OK);
        printf("%s parse success.\n", passFiles[i]);
    }

    const char* failFiles[] = {
        "./data/json/fail1.json",       // Unclosed property name.
        "./data/json/fail2.json",       // Illegal object syntax.
        "./data/json/fail3.json",       // Property name without end quote.
        "./data/json/fail4.json",       // Property name without start quote.
        "./data/json/fail5.json",       // Illegal object syntax.
        "./data/json/fail6.json",       // Unclosed array.
        "./data/json/fail7.json",       // Typo true1.
        "./data/json/fail8.json",       // Typo false1.
        "./data/json/fail9.json",       // Typo null.
        "./data/json/failnum1.json",    // Unlike C, 00 is invalid.
        "./data/json/failnum2.json",    // Unlike C, +number is invalid.
        "./data/json/failnum3.json",    // Unlike C, .number is invalid.
        "./data/json/failnum4.json",    // Unlike C, number. is invalid.
        "./data/json/failnum5.json",    // Missing fractional digit after '.'.
        "./data/json/failnum6.json",    // Missing exponent after sign.
        "./data/json/failstring1.json", // Missing end quote.
        "./data/json/failstring2.json", // Single quoted string.
        "./data/json/failstring3.json", // Illegal escape character.
        "./data/json/failstring4.json", // Illegal \U instead of \u.
        "./data/json/failstring5.json", // Missing digit in unicode escape
                                        // sequence.
        "./data/json/failstring6.json"  // Unexpected eof.
    };

    for (size_t i = 0; i < OE_COUNTOF(failFiles); ++i)
    {
        OE_TEST(ParseJson(enclave, failFiles[i]) == OE_FAILURE);
        printf("%s parse failed as expected.\n", failFiles[i]);
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

    uint8_t expectedFmSpc[6] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};
    OE_TEST(
        memcmp(parsedInfo.fmspc, expectedFmSpc, sizeof(expectedFmSpc)) == 0);

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

    const uint8_t expectedSignature[] = {
        0x62, 0xd1, 0x81, 0xc4, 0xba, 0x86, 0x32, 0x13, 0xb8, 0x25, 0xd1,
        0xc0, 0xb6, 0x6b, 0x92, 0xa3, 0xdb, 0xdb, 0x27, 0xb8, 0xff, 0x7c,
        0x72, 0x50, 0xcb, 0x2b, 0x2a, 0xb8, 0x7a, 0x8f, 0x90, 0xd5, 0xe5,
        0xa1, 0x41, 0x69, 0x14, 0x36, 0x9d, 0x8f, 0x82, 0xc5, 0x6c, 0xd3,
        0xd8, 0x75, 0xca, 0xa5, 0x4a, 0xe4, 0xb9, 0x17, 0xca, 0xf4, 0xaf,
        0x7a, 0x93, 0xde, 0xc5, 0x20, 0x67, 0xcb, 0xfd, 0x7b};
    oe_hex_dump(parsedInfo.signature, sizeof(parsedInfo.signature));
    OE_TEST(
        memcmp(
            parsedInfo.signature,
            expectedSignature,
            sizeof(expectedSignature)) == 0);

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
