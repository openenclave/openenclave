#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/utils.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/error.h>
#include "../args.h"

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;
    Args args;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    /* Create the enclave */
    if ((result = OE_CreateEnclave(argv[1], OE_FLAG_DEBUG, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    /* Clear the arguments */
    memset(&args, 0, sizeof(args));

    /* Initialize the quote */
    {
        SGX_EPIDGroupID egid;

        if ((result = SGX_InitQuote(&args.targetInfo, &egid)) != OE_OK)
        {
            OE_PutErr("OE_InitQuote(): result=%u", result);
        }
    }

    /* Get the report */
    if (OE_CallEnclave(enclave, "GetReport", &args) != OE_OK)
    {
        OE_PutErr("OE_CallEnclave(): result=%u", result);
    }

#if 0
    __OE_HexDump(&args.report, sizeof(SGX_Report));
#endif

    SGX_SPID spid = 
    {
        {
            0x21, 0x68, 0x79, 0xB4, 0x42, 0xA0, 0x4A, 0x07,
            0x60, 0xF6, 0x39, 0x91, 0x7F, 0x4E, 0x8B, 0x04,
        }
    };

    /* Get the quote */
    {
        SGX_Quote quote;
        memset(&quote, 0xDD, sizeof(quote));

        if ((result = SGX_GetQuote(
            &args.report,
            SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
            &spid,
            NULL, /* nonce */
            NULL, /* signatureRevocationList */
            0, /* signatureRevocationListSize */
            NULL, /* reportOut */
            &quote,
            sizeof(SGX_Quote))) != OE_OK)
        {
            OE_PutErr("__SGX_GetQuote(): result=%u", result);
        }

#if 0
        __OE_HexDump(&quote, sizeof(quote));
#endif
    }

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
