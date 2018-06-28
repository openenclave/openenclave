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
#include "../common/tests.cpp"

#define SKIP_RETURN_CODE 2

std::vector<uint8_t> FileToBytes(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
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

void TestVerifyTCBInfo(oe_enclave_t* enclave)
{
    std::vector<uint8_t> tcbInfo = FileToBytes("./data/tcbInfo.json");
    OE_ParsedTcbInfo parsedInfo = {0};
    VerifyTCBInfoArgs args = {
        &tcbInfo[0], (uint32_t)tcbInfo.size(), &parsedInfo};

    OE_TEST(
        oe_call_enclave(enclave, "TestVerifyTCBInfo", &args) == OE_OK &&
        args.result == OE_OK);

    OE_TEST(parsedInfo.version == 1);
    OE_TEST(
        CheckParsedString(
            parsedInfo.issueDate,
            parsedInfo.issueDateSize,
            "2018-06-06T10:12:17.085Z"));
    OE_TEST(
        CheckParsedString(
            parsedInfo.fmspc, parsedInfo.fmspcSize, "00906EA10000"));

    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[0] == 4);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[1] == 4);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[2] == 2);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[3] == 4);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[4] == 1);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[5] == 128);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[6] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[7] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[8] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[9] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[10] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[11] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[12] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[13] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[14] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].sgxTCBCompSvn[15] == 0);
    OE_TEST(parsedInfo.tcbLevels[0].pceSvn == 5);
    OE_TEST(parsedInfo.tcbLevels[0].status == OE_TCB_STATUS_UP_TO_DATE);

    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[0] == 2);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[1] == 2);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[2] == 2);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[3] == 4);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[4] == 1);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[5] == 128);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[6] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[7] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[8] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[9] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[10] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[11] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[12] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[13] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[14] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].sgxTCBCompSvn[15] == 0);
    OE_TEST(parsedInfo.tcbLevels[1].pceSvn == 4);
    OE_TEST(parsedInfo.tcbLevels[1].status == OE_TCB_STATUS_OUT_OF_DATE);

    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[0] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[1] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[2] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[3] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[4] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[5] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[6] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[7] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[8] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[9] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[10] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[11] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[12] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[13] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[14] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].sgxTCBCompSvn[15] == 0);
    OE_TEST(parsedInfo.tcbLevels[2].pceSvn == 0);
    OE_TEST(parsedInfo.tcbLevels[2].status == 0);

    OE_TEST(
        CheckParsedString(
            parsedInfo.signature,
            parsedInfo.signatureSize,
            "62d181c4ba863213b825d1c0b66b92a3dbdb27b8ff7c7250cb2b2ab87a8f90d5e5"
            "a1416914369d8f82c56cd3d875caa54ae4b917caf4af7a93dec52067cbfd7b"));

    printf("TestVerifyTCBInfo: Positive Test passed\n");

    const char* negativeFiles[] = {
        // In the following files, a property in corresponding level starts with
        // capital letter. JSON is case sensitive and therefore schema
        // validation should fail.
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
        OE_ParsedTcbInfo parsedInfo = {0};
        VerifyTCBInfoArgs args = {
            &tcbInfo[0], (uint32_t)tcbInfo.size(), &parsedInfo};
        OE_TEST(
            oe_call_enclave(enclave, "TestVerifyTCBInfo", &args) == OE_OK &&
            args.result == OE_FAILURE);
        printf("TestVerifyTCBInfo: Negative Test %lu passed\n", i);
    }
}

int main(int argc, const char* argv[])
{
    sgx_target_info_t targetInfo;
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Create the enclave */
    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    /* Initialize the target info */
    {
        if ((result = sgx_get_qetarget_info(&targetInfo)) != OE_OK)
        {
            oe_put_err("sgx_get_qetarget_info(): result=%u", result);
        }
    }

    /*
     * Host API tests.
     */
    g_Enclave = enclave;
//     TestLocalReport(&targetInfo);
//     TestRemoteReport(NULL);
//     TestParseReportNegative(NULL);
//     TestLocalVerifyReport(NULL);

// #ifdef OE_USE_LIBSGX
//     TestRemoteVerifyReport(NULL);
// #endif

/*
 * Enclave API tests.
 */

// OE_TEST(oe_call_enclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

// OE_TEST(oe_call_enclave(enclave, "TestRemoteReport", &targetInfo) == OE_OK);

// OE_TEST(
//     oe_call_enclave(enclave, "TestParseReportNegative", &targetInfo) ==
//     OE_OK);

// OE_TEST(
//     oe_call_enclave(enclave, "TestLocalVerifyReport", &targetInfo) ==
//     OE_OK);

#ifdef OE_USE_LIBSGX
    // OE_TEST(
    //     oe_call_enclave(enclave, "TestRemoteVerifyReport", &targetInfo) ==
    //     OE_OK);

    TestVerifyTCBInfo(enclave);
#endif

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
