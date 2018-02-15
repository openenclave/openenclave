#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SampleAppAttestationShared.h"

unsigned char SampleReportData[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

char ReportBuf[512];

OE_ECALL void GetAppEnclaveReport(void* Args)
{
    //
    // Verify the input paramter is from share memory(e.g. not inside enclave).
    //

    if (!OE_IsOutsideEnclave(Args, sizeof(CREATE_APP_ENCLAVE_REPORT_ARGS)))
    {
        return;
    }

    auto CreateReportArgs = (CREATE_APP_ENCLAVE_REPORT_ARGS*)Args;
    if ((CreateReportArgs->ReportSize != 0) && CreateReportArgs->Report == nullptr)
    {
        CreateReportArgs->Result = OE_INVALID_PARAMETER;
        return;
    }

    //
    // Verify the report buffer of input paramter is from share memory(e.g. not inside enclave).
    //

    if ((CreateReportArgs->ReportSize != 0) &&
        !OE_IsOutsideEnclave(CreateReportArgs->Report, CreateReportArgs->ReportSize))
    {
        CreateReportArgs->Result = OE_INVALID_PARAMETER;
        return;
    }

    //
    // Get size of report.
    //

    size_t ReportSize = 0;
    OE_Result Result = OE_GetReportForRemoteAttestation(nullptr, nullptr, &ReportSize);
    if (Result != OE_BUFFER_TOO_SMALL)
    {
        CreateReportArgs->Result = Result;
        return;
    }

    if (CreateReportArgs->ReportSize < ReportSize)
    {
        CreateReportArgs->Result = OE_BUFFER_TOO_SMALL;
        CreateReportArgs->ReportSize = ReportSize;
        return;
    }

    //
    // Set the reportData, usually it is the hash of user data.
    //
    //

    uint8_t ReportData[OE_REPORT_DATA_SIZE];
    memset(ReportData, 0, sizeof(ReportData));
    memcpy(ReportData, SampleReportData, sizeof(SampleReportData));

    //
    // Allocate memory for SGX_REPORT which must be inside enclave.
    //

    void* Report = malloc(ReportSize);
    if (Report == nullptr)
    {
        CreateReportArgs->Result = OE_OUT_OF_MEMORY;
        return;
    }

    //
    // Generate report and copy it to output buffer if success.
    //

    CreateReportArgs->Result = OE_GetReportForRemoteAttestation(ReportData, Report, &ReportSize);
    if (CreateReportArgs->Result == OE_OK)
    {
        memcpy(CreateReportArgs->Report, Report, ReportSize);
        CreateReportArgs->ReportSize = ReportSize;
    }

//
// Free memory and return.
//

#if 0
    free(Report);
#endif
    Report = nullptr;

    return;
}
