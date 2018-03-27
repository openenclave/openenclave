// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define SKIP_RETURN_CODE 2

static bool CheckReportData(
    uint8_t* reportBuffer,
    uint32_t reportSize,
    const uint8_t* reportData,
    uint32_t reportDataSize)
{
    for (uint32_t i = 0; i < reportSize - reportDataSize; ++i)
    {
        if (memcmp(reportBuffer + i, reportData, reportDataSize) == 0)
            return true;
    }
    return false;
}

static void TestLocalReport(OE_Enclave* enclave, SGX_TargetInfo* targetInfo)
{
    uint32_t reportDataSize = 0;
    uint8_t reportData[OE_REPORT_DATA_SIZE];
    for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
        reportData[i] = i;

    const uint8_t zeros[OE_REPORT_DATA_SIZE] = {0};

    uint32_t reportSize = 1024;
    uint8_t reportBuffer[1024];

    uint8_t optParams[sizeof(SGX_TargetInfo)];
    for (uint32_t i = 0; i < sizeof(optParams); ++i)
        optParams[i] = 0;

    /*
     * Post conditions:
     *     1. On a successfull call, the returned report size must always be
     * sizeof(SGX_Report);
     *     2. Report must contain specified report data or zeros as report data.
     */

    /*
     * Report data parameters scenarios:
     *      a. Report data can be NULL.
     *      b. Report data can be < OE_REPORT_DATA_SIZE
     *      c. Report data can be OE_REPORT_DATA_SIZE
     *      d. Report data cannot exceed OE_REPORT_DATA_SIZE
     */
    {
        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
                enclave, 0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, zeros, OE_REPORT_DATA_SIZE));

        reportSize = 1024 * 1024;
        reportDataSize = 16;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize + 1) ==
            false);

        reportSize = 1024 * 1024;
        reportDataSize = OE_REPORT_DATA_SIZE;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize));

        reportSize = 1024 * 1024;
        reportDataSize = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
    }

    /*
     * optParams scenarios:
     *     1. If optParams is not null, optParamsSize must be
     * sizeof(SGX_TargetInfo)
     *     2. Otherwise, both must be null/0.
     *     3. optParams can be zeroed out target info.
     *     4. optParams can be a valid target info.
     */
    {
        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            OE_GetReport(
                enclave, 0, NULL, 0, optParams, 5, reportBuffer, &reportSize) ==
            OE_INVALID_PARAMETER);

        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
                enclave, 0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));

        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                NULL,
                0,
                optParams,
                sizeof(SGX_TargetInfo),
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));

        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
                enclave,
                0,
                NULL,
                0,
                targetInfo,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     *     b. Size too small.
     */
    {
        reportSize = 1024 * 1204;
        OE_TEST(
            OE_GetReport(enclave, 0, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        reportSize = 1;
        OE_TEST(
            OE_GetReport(
                enclave, 0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
    }
}

static void TestRemoteReport(OE_Enclave* enclave)
{
    uint32_t reportDataSize = 0;
    uint8_t reportData[OE_REPORT_DATA_SIZE];
    for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
        reportData[i] = i;

    const uint8_t zeros[OE_REPORT_DATA_SIZE] = {0};

    uint32_t reportSize = 2048;
    uint8_t reportBuffer[2048];

    uint8_t optParams[sizeof(SGX_TargetInfo)];
    for (uint32_t i = 0; i < sizeof(optParams); ++i)
        optParams[i] = 0;

    uint32_t options = OE_REPORT_OPTIONS_REMOTE_ATTESTATION;
    /*
     * Post conditions:
     *     1. Report must contain specified report data or zeros as report data.
     */

    /*
     * Report data parameters scenarios:
     *      a. Report data can be NULL.
     *      b. Report data can be < OE_REPORT_DATA_SIZE
     *      c. Report data can be OE_REPORT_DATA_SIZE
     *      d. Report data cannot exceed OE_REPORT_DATA_SIZE
     */
    {
        reportSize = 2048;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                NULL,
                0,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, zeros, OE_REPORT_DATA_SIZE));

        reportSize = 2048;
        reportDataSize = 16;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize + 1) ==
            false);

        reportSize = 2048;
        reportDataSize = OE_REPORT_DATA_SIZE;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, reportData, reportDataSize));

        reportSize = 2048;
        reportDataSize = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
    }

    /*
     * optParams scenarios:
     *     1. Both optParams and optParamsSize must be NULL/0.
     */
    {
        reportSize = 2048;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                NULL,
                0,
                optParams,
                5,
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     *     b. Size too small.
     */
    {
        reportSize = 2048;
        OE_TEST(
            OE_GetReport(
                enclave, options, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        reportSize = 1;
        OE_TEST(
            OE_GetReport(
                enclave,
                options,
                NULL,
                0,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_BUFFER_TOO_SMALL);
    }
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
    if ((flags & OE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Create the enclave */
    if ((result = OE_CreateEnclave(argv[1], OE_FLAG_DEBUG, &enclave)) != OE_OK)
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
    TestLocalReport(enclave, &targetInfo);
    TestRemoteReport(enclave);

    /*
     * Enclave API tests.
     */
    assert(OE_CallEnclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
