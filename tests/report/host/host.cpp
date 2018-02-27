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

void DumpReport(SGX_Report* report)
{
    printf("=== SGX_Report:\n");

    printf("body=");
    __OE_HexDump(&report->body, sizeof(report->body));
    printf("\n");

    printf("keyid=");
    __OE_HexDump(&report->keyid, sizeof(report->keyid));
    printf("\n");

    printf("mac=");
    __OE_HexDump(&report->mac, sizeof(report->mac));
    printf("\n");

    printf("\n");
}

void DumpQuote(SGX_Quote* quote)
{
    printf("=== SGX_Quote:\n");
    printf("version=%u\n", quote->version);
    printf("sign_type=%u\n", quote->sign_type);

    printf("epid_group_id=");
    __OE_HexDump(&quote->epid_group_id, sizeof(quote->epid_group_id));
    printf("\n");

    printf("qe_svn=%u\n", quote->qe_svn);
    printf("pce_svn=%u\n", quote->pce_svn);
    printf("xeid=%u\n", quote->xeid);

    printf("basename=");
    __OE_HexDump(quote->basename, sizeof(quote->basename));
    printf("\n");

    printf("report_body=");
    __OE_HexDump(&quote->report_body, sizeof(quote->report_body));
    printf("\n");

    printf("signature_len=%u\n", quote->signature_len);

    printf("signature=");
    __OE_HexDump(quote->signature, quote->signature_len);
    printf("\n");

    printf("\n");
}

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
    DumpReport(&args.report);
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
        memset(&quote, 0, sizeof(quote));

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

#if 1
        DumpQuote(&quote);
#endif

        /* Verify that the quote contains the report */
        assert(memcmp(
            &args.report.body,
            &quote.report_body,
            sizeof(SGX_ReportBody)) == 0);
    }

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
