// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>

#include <fstream>
#include <streambuf>
#include <vector>
#include "../common/args.h"
#include "../common/tests.cpp"

#define SKIP_RETURN_CODE 2

std::vector<uint8_t> fileToBytes(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}
void TestVerifyQuote()
{
    VerifyQuoteArgs args = {0};
    std::vector<uint8_t> quote =
        fileToBytes("./../../../tests/report/data/quote.dat");
    std::vector<uint8_t> pckCert =
        fileToBytes("./../../../tests/report/data/pckCert.pem");
    std::vector<uint8_t> pckCrl =
        fileToBytes("./../../../tests/report/data/intermediateCaCrl.pem");
    std::vector<uint8_t> tcbInfo =
        fileToBytes("./../../../tests/report/data/tcbInfo.json");

    if (pckCert.back() != '\0')
        pckCert.push_back('\0');

    args.quote = &quote[0];
    args.quoteSize = quote.size();
    args.pemPckCertificate = &pckCert[0];
    args.pemPckCertificateSize = pckCert.size();
    args.pckCrl = &pckCrl[0];
    args.pckCrlSize = pckCrl.size();
    args.tcbInfoJson = &tcbInfo[0];
    args.tcbInfoJsonSize = tcbInfo.size();

    OE_TEST(OE_CallEnclave(g_Enclave, "VerifyQuote", &args) == OE_OK);
    OE_TEST(args.result == OE_OK);
}

int main(int argc, const char* argv[])
{
    SGX_TargetInfo targetInfo;
    OE_Result result;
    OE_Enclave* enclave = NULL;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Create the enclave */
    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    /* Initialize the target info */
    {
        SGX_EPIDGroupID egid;

        if ((result = SGX_InitQuote(&targetInfo, &egid)) != OE_OK)
        {
            OE_PutErr("OE_InitQuote(): result=%u", result);
        }
    }

    /*
     * Host API tests.
     */
    g_Enclave = enclave;
    TestLocalReport(&targetInfo);
    TestRemoteReport(NULL);
    TestParseReportNegative(NULL);
    TestLocalVerifyReport(NULL);

    /*
     * Enclave API tests.
     */

    OE_TEST(OE_CallEnclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

    OE_TEST(OE_CallEnclave(enclave, "TestRemoteReport", &targetInfo) == OE_OK);

    OE_TEST(
        OE_CallEnclave(enclave, "TestParseReportNegative", &targetInfo) ==
        OE_OK);

    OE_TEST(
        OE_CallEnclave(enclave, "TestLocalVerifyReport", &targetInfo) == OE_OK);

    TestVerifyQuote();

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
