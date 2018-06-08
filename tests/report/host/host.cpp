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
void TestVerifyQuote()
{
    VerifyQuoteArgs args = {0};
    std::vector<uint8_t> quote = FileToBytes("./data/quote.dat");
    std::vector<uint8_t> pckCert = FileToBytes("./data/pckCert.pem");
    std::vector<uint8_t> pckCrl = FileToBytes("./data/intermediateCaCrl.pem");
    std::vector<uint8_t> tcbInfo = FileToBytes("./data/tcbInfo.json");

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

    OE_TEST(oe_call_enclave(g_Enclave, "VerifyQuote", &args) == OE_OK);
    OE_TEST(args.result == OE_OK);
}

int main(int argc, const char* argv[])
{
    SGX_TargetInfo targetInfo;
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
        oe_puterr("oe_create_enclave(): result=%u", result);
    }

    /* Initialize the target info */
    {
        if ((result = SGX_GetQETargetInfo(&targetInfo)) != OE_OK)
        {
            oe_puterr("SGX_GetQETargetInfo(): result=%u", result);
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

#ifdef OE_USE_LIBSGX
    TestRemoteVerifyReport(NULL);
#endif

    /*
     * Enclave API tests.
     */

    OE_TEST(oe_call_enclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

    OE_TEST(oe_call_enclave(enclave, "TestRemoteReport", &targetInfo) == OE_OK);

    OE_TEST(
        oe_call_enclave(enclave, "TestParseReportNegative", &targetInfo) ==
        OE_OK);

    OE_TEST(
        oe_call_enclave(enclave, "TestLocalVerifyReport", &targetInfo) == OE_OK);

#ifdef OE_USE_LIBSGX
    OE_TEST(
        oe_call_enclave(enclave, "TestRemoteVerifyReport", &targetInfo) ==
        OE_OK);

    TestVerifyQuote();
#endif

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_puterr("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
