#include <assert.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    OE_HexDump(&args.report, sizeof(SGX_Report));
#endif

    SGX_SPID spid = {{
        0x21,
        0x68,
        0x79,
        0xB4,
        0x42,
        0xA0,
        0x4A,
        0x07,
        0x60,
        0xF6,
        0x39,
        0x91,
        0x7F,
        0x4E,
        0x8B,
        0x04,
    }};

    /* Get the quote */
    {
        SGX_Quote* quote;
        size_t quoteSize;

        /* Get the quote size without a signature revocation list */
        if ((result = SGX_GetQuoteSize(NULL, &quoteSize)) != OE_OK)
        {
            OE_PutErr("SGX_GetQuoteSize(): result=%u", result);
        }

        /* Allocate the structure */
        if (!(quote = (SGX_Quote*)malloc(quoteSize)))
        {
            OE_PutErr("malloc(): failed");
        }

        /* Clear the quote structure */
        memset(quote, 0xDD, quoteSize);

        if ((result = SGX_GetQuote(
                 &args.report,
                 SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE,
                 &spid,
                 NULL, /* nonce */
                 NULL, /* signatureRevocationList */
                 0,    /* signatureRevocationListSize */
                 NULL, /* reportOut */
                 quote,
                 quoteSize)) != OE_OK)
        {
            OE_PutErr("SGX_GetQuote(): result=%u", result);
        }

        /* Verify that quote contains report body */
        assert(
            memcmp(
                &args.report.body,
                &quote->report_body,
                sizeof(SGX_ReportBody)) == 0);

        /* Verify that quote type is correct */
        assert(quote->sign_type == SGX_QUOTE_TYPE_UNLINKABLE_SIGNATURE);

        /* Verify that signature length is non-zero */
        assert(quote->signature_len != 0);

        /* Verify that signature is not zero-filled */
        {
            const uint8_t* p = quote->signature;
            const uint8_t* end = quote->signature + quote->signature_len;

            /* Skip over zero bytes */
            while (p != end && *p == '\0')
                p++;

            /* Fail if a non-zero byte was not found */
            assert(p != end);
        }

        /* Free the quote structure */
        free(quote);
    }

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
