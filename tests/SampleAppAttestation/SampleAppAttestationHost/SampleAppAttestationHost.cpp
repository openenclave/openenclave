#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <openenclave/host.h>
#include "../SampleAppAttestation/SampleAppAttestationShared.h"

#define TRACE printf("TRACE: %s(%u): %s()\n", __FILE__, __LINE__, __FUNCTION__)

OE_Result
HostGetAppEnclaveReport(
    OE_Enclave* enclave,
    void **Report,
    size_t* ReportSize
)
{
    OE_Result Result;
    CREATE_APP_ENCLAVE_REPORT_ARGS Args { OE_OK };

    //
    // Call into enclave to get needed report size.
    //

    if (OE_CallEnclave(enclave, "GetAppEnclaveReport", &Args) != OE_OK)
    {
        printf("Error failed callin with error\n");
        Result = OE_FAILURE;
        goto Cleanup;
    }

    if (Args.Result != OE_BUFFER_TOO_SMALL)
    {
        printf("Failed to get needed report size [%x]\n", Args.Result);
        Result = OE_FAILURE;
        goto Cleanup;
    }

    //
    // Allocate memory in host for output report.
    //

    Args.Report = malloc(Args.ReportSize);
    if (Args.Report == NULL)
    {
        Result = OE_OUT_OF_MEMORY;
        goto Cleanup;
    }

    //
    // Call into enclave to get report.
    //

    if (OE_CallEnclave(enclave, "GetAppEnclaveReport", &Args) != OE_OK)
    {
        printf("Error failed callin with error\n");
        Result = OE_FAILURE;
        goto Cleanup;
    }

    Result = Args.Result;
    if (Result == OE_OK)
    {
        *Report = Args.Report;
        *ReportSize = Args.ReportSize;
    }


Cleanup:
    if (Result != OE_OK)
    {
        if (Args.Report != NULL)
        {
            free(Args.Report);
            Args.Report = NULL;
        }
    }

    return Result;
}

OE_Result
GetQuoteWrapper(
    void *Report,
    size_t ReportSize,
    void **Quote,
    size_t *QuoteSize
)
{
    OE_Result Result;
    *Quote = NULL;
    *QuoteSize = 0;

    //
    // Get needed quote size.
    //

    Result = OE_GetQuote(Report,
                      ReportSize,
                      NULL,
                      QuoteSize);

    if (Result != OE_BUFFER_TOO_SMALL)
    {
        printf("Error: OE_GetQuote(): %u\n", Result);
        goto Cleanup;
    }

    //
    // Allocate memory in host for the output quote.
    //

    *Quote = malloc(*QuoteSize);
    if (*Quote == NULL)
    {
        Result = OE_OUT_OF_MEMORY;
        goto Cleanup;
    }

    //
    // Get quote.
    //

    Result = OE_GetQuote(Report,
                      ReportSize,
                      *Quote,
                      QuoteSize);
    if (Result != OE_OK)
    {
        printf("Error: OE_GetQuote(): %u\n", Result);
        printf("Failed to get needed quote [%x]\n", Result);
        goto Cleanup;
    }

Cleanup:
    if (Result != OE_OK)
    {
        if (*Quote != NULL)
        {
            free(*Quote);
            *Quote = NULL;
        }
    }

    return Result;
}

bool SaveQuoteToFile(
    const char *Filename,
    void *Quote,
    size_t QuoteSize
)
{
    std::ofstream fileStream;
    fileStream.open(Filename, std::ios::binary);
    if (!fileStream.good()) {
        printf("%s can't be created.\n", Filename);
        return false;
    }

    //
    // Save the quote blob to file.
    //

    fileStream.write((const char*)&QuoteSize, sizeof(QuoteSize));
    fileStream.write((const char*)Quote, QuoteSize);

    return true;
}

bool
GetEnclaveQuote(
    OE_Enclave* enclave,
    const char* Filename
)
{
    bool Result = false;
    OE_Result Status;
    void *Report = NULL;
    size_t ReportSize = 0;
    void *Quote = NULL;
    size_t QuoteSize = 0;

    Status = HostGetAppEnclaveReport(enclave, &Report, &ReportSize);
    if (Status != OE_OK)
    {
        printf("Error: HostGetAppEnclaveReport(): %u\n", Status);
        goto Cleanup;
    }

    Status = GetQuoteWrapper(Report, ReportSize, &Quote, &QuoteSize);
    if (Status != OE_OK)
    {
        printf("Error: GetQuoteWrapper(): %u\n", Status);
        goto Cleanup;
    }

    if (!SaveQuoteToFile(Filename, Quote, QuoteSize))
    {
        goto Cleanup;
    }

    Result = true;

Cleanup:
    if (Report != NULL)
    {
#if 0
        free(Report);
#endif
        Report = NULL;
    }

    if (Quote != NULL)
    {
#if 0
        free(Quote);
#endif
        Quote = NULL;
    }

    return Result;
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr,
            "Usage: SampleAppAttestationHost.exe <path to  packaged enc/dev dll>\n"
            "Example: SampleAppAttestationHost.exe SampleAppAttestation.dev.pkg\\SampleAppAttestation.dll\n");
        return 1;
    }

    result = OE_CreateEnclave(argv[1], OE_FLAG_DEBUG, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create enclave, result=%d\n", result);
        return 1;
    }

    const char *Filename = "SampleAppEnclaveQuote.bin";

    //
    // Get the app enclave quote, and save the quote blob to disk file.
    //

    if (GetEnclaveQuote(enclave, Filename))
    {
#ifdef TRACEON
        printf("GetEnclaveQuote, quote is saved to %s\n", Filename);
#endif
    }
    else 
    {
        fprintf(stderr, "%s: GetEnclaveQuote failed.\n", argv[0]);
        return 1;
    }

#ifdef TRACEON
    fprintf(stdout, "Successfully finished SampleAppAttestationHost\n");
#endif

    printf("=== passed all tests (SampleAppAttestation)\n");

    OE_TerminateEnclave(enclave);
    return 0;
}
