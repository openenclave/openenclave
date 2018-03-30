// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Define this for OE_TEST to work without stdio.h being available.
#define OE_BUILD_ENCLAVE

#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/tests.h>
#include <openenclave/enclave.h>

static bool CheckReportData(
    uint8_t* reportBuffer,
    uint32_t reportSize,
    const uint8_t* reportData,
    uint32_t reportDataSize)
{
    for (uint32_t i = 0; i < reportSize - reportDataSize; ++i)
    {
        if (OE_Memcmp(reportBuffer + i, reportData, reportDataSize) == 0)
            return true;
    }
    return false;
}

OE_ECALL void TestLocalReport(void* args_)
{
    SGX_TargetInfo* targetInfo = (SGX_TargetInfo*)args_;
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
     *      1. Report data can be NULL.
     *      2. Report data can be < OE_REPORT_DATA_SIZE
     *      3. Report data can be OE_REPORT_DATA_SIZE
     *      4. Report data cannot exceed OE_REPORT_DATA_SIZE
     */
    {
        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, zeros, OE_REPORT_DATA_SIZE));

        reportSize = 1024 * 1024;
        reportDataSize = 16;
        OE_TEST(
            OE_GetReport(
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
                0,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            OE_GetReport(0, NULL, 0, optParams, 5, reportBuffer, &reportSize) ==
            OE_INVALID_PARAMETER);

        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));

        reportSize = 1024 * 1024;
        OE_TEST(
            OE_GetReport(
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
            OE_GetReport(0, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        reportSize = 1;
        OE_TEST(
            OE_GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
    }
}

OE_ECALL void TestRemoteReport(void* args_)
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
                options, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);
        OE_TEST(
            CheckReportData(
                reportBuffer, reportSize, zeros, OE_REPORT_DATA_SIZE));

        reportSize = 2048;
        reportDataSize = 16;
        OE_TEST(
            OE_GetReport(
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
                options,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            OE_GetReport(
                options, NULL, 0, optParams, 5, reportBuffer, &reportSize) ==
            OE_INVALID_PARAMETER);
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     *     b. Size too small.
     */
    {
        reportSize = 2048;
        OE_TEST(
            OE_GetReport(options, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        reportSize = 1;
        OE_TEST(
            OE_GetReport(
                options, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
    }
}
