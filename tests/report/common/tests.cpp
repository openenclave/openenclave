// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE

#define Memset OE_Memset
#define Memcpy OE_Memcpy
#define Memcmp OE_Memcmp

#define GetReport OE_GetReport

#define VerifyReport OE_VerifyReport

#define TEST_FCN OE_ECALL

#else

#define Memset memset
#define Memcpy memcpy
#define Memcmp memcmp

// The host side API requires the enclave to be passed in.

OE_Enclave* g_Enclave = NULL;

#define GetReport(opt, rd, rds, op, ops, rb, rbs) \
    OE_GetReport(g_Enclave, opt, rd, rds, op, ops, rb, rbs)

#define VerifyReport(rpt, rptSize, pr) \
    OE_VerifyReport(g_Enclave, rpt, rptSize, pr)

#define TEST_FCN

#endif

/*
 * g_UniqueID is populated from the first call to OE_ParseReport.
 * The enclave's uniqueID is asserted to not change subsequently.
 */
uint8_t g_UniqueID[32];

uint8_t g_AuthorID[32] = {0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
                          0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
                          0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
                          0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

uint8_t g_ProductID[16] = {0};

static bool CheckReportData(
    uint8_t* reportBuffer,
    uint32_t reportSize,
    const uint8_t* reportData,
    uint32_t reportDataSize)
{
    OE_Report parsedReport = {0};
    OE_TEST(OE_ParseReport(reportBuffer, reportSize, &parsedReport) == OE_OK);

    return (Memcmp(parsedReport.reportData, reportData, reportDataSize) == 0);
}

static void ValidateReport(
    uint8_t* reportBuffer,
    uint32_t reportSize,
    bool remote,
    const uint8_t* reportData,
    uint32_t reportDataSize)
{
    SGX_Quote* sgxQuote = NULL;
    SGX_Report* sgxReport = NULL;

    OE_Report parsedReport = {0};

    static bool firstTime = true;

    OE_TEST(OE_ParseReport(reportBuffer, reportSize, &parsedReport) == OE_OK);

    /* Validate header. */
    OE_TEST(parsedReport.type == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(Memcmp(parsedReport.reportData, reportData, reportDataSize) == 0);

    /* Validate pointer fields. */
    if (remote)
    {
        sgxQuote = (SGX_Quote*)reportBuffer;
        OE_TEST(reportSize >= sizeof(SGX_Quote));

        OE_TEST(
            parsedReport.reportData == sgxQuote->report_body.reportData.field);
        OE_TEST(parsedReport.reportDataSize == sizeof(SGX_ReportData));
        OE_TEST(parsedReport.enclaveReport == (uint8_t*)&sgxQuote->report_body);
        OE_TEST(parsedReport.enclaveReportSize == sizeof(SGX_ReportBody));
    }
    else
    {
        OE_TEST(reportSize == sizeof(SGX_Report));
        sgxReport = (SGX_Report*)reportBuffer;

        OE_TEST(parsedReport.reportData == sgxReport->body.reportData.field);
        OE_TEST(parsedReport.reportDataSize == sizeof(SGX_ReportData));
        OE_TEST(parsedReport.enclaveReport == (uint8_t*)&sgxReport->body);
        OE_TEST(parsedReport.enclaveReportSize == sizeof(SGX_ReportBody));
    }

    /* Validate identity. */
    OE_TEST(parsedReport.identity.idVersion == 0x0);
    OE_TEST(parsedReport.identity.securityVersion == 0x0);

    OE_TEST(parsedReport.identity.attributes & OE_REPORT_ATTRIBUTES_DEBUG);

    OE_TEST(
        !(parsedReport.identity.attributes & OE_REPORT_ATTRIBUTES_RESERVED));

    OE_TEST(
        (bool)(parsedReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE) ==
        remote);

    if (firstTime)
    {
        Memcpy(
            g_UniqueID,
            parsedReport.identity.uniqueID,
            sizeof(parsedReport.identity.uniqueID));

        firstTime = false;
    }

    OE_TEST(
        Memcmp(
            parsedReport.identity.uniqueID,
            g_UniqueID,
            sizeof(parsedReport.identity.uniqueID)) == 0);

    OE_TEST(
        Memcmp(
            parsedReport.identity.authorID,
            g_AuthorID,
            sizeof(parsedReport.identity.authorID)) == 0);

    OE_TEST(
        Memcmp(
            parsedReport.identity.productID,
            g_ProductID,
            sizeof(parsedReport.identity.productID)) == 0);
}

TEST_FCN void TestLocalReport(void* args_)
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
     *     1. On a successful call, the returned report size must always be
     *        sizeof(SGX_Report);
     *     2. Report must contain specified report data or zeros as report data.
     */

    /*
     * Report data parameters scenarios on enclave side:
     *      1. Report data can be NULL.
     *      2. Report data can be < OE_REPORT_DATA_SIZE
     *      3. Report data can be OE_REPORT_DATA_SIZE
     *      4. Report data cannot exceed OE_REPORT_DATA_SIZE
     *
     * Report data must always be null on host side.
     */
    {
#ifdef OE_BUILD_ENCLAVE
        OE_Result expectedResult = OE_OK;
#else
        OE_Result expectedResult = OE_INVALID_PARAMETER;
#endif

        reportSize = 1024 * 1024;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);

        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, zeros, OE_REPORT_DATA_SIZE);
        }

        reportSize = 1024 * 1024;
        reportDataSize = 16;
        OE_TEST(
            GetReport(
                0,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, reportData, reportDataSize);

            OE_TEST(
                CheckReportData(
                    reportBuffer, reportSize, reportData, reportDataSize + 1) ==
                false);
        }

        reportSize = 1024 * 1024;
        reportDataSize = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport(
                0,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);

        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, reportData, reportDataSize);
        }

        reportSize = 1024 * 1024;
        reportDataSize = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            GetReport(
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
            GetReport(
                0,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(0, NULL, 0, optParams, 5, reportBuffer, &reportSize) ==
            OE_INVALID_PARAMETER);

        reportSize = 1024 * 1024;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);
        ValidateReport(
            reportBuffer, reportSize, false, zeros, OE_REPORT_DATA_SIZE);

        reportSize = 1024 * 1024;
        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                optParams,
                sizeof(SGX_TargetInfo),
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        ValidateReport(
            reportBuffer, reportSize, false, zeros, OE_REPORT_DATA_SIZE);

        reportSize = 1024 * 1024;
        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                targetInfo,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == sizeof(SGX_Report));
        ValidateReport(
            reportBuffer, reportSize, false, zeros, OE_REPORT_DATA_SIZE);
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     *     b. Size too small.
     */
    {
        reportSize = 1024 * 1204;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
        OE_TEST(reportSize == sizeof(SGX_Report));

        reportSize = 1;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
        OE_TEST(reportSize == sizeof(SGX_Report));
    }
}

TEST_FCN void TestRemoteReport(void* args_)
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
#ifdef OE_BUILD_ENCLAVE
        OE_Result expectedResult = OE_OK;
#else
        OE_Result expectedResult = OE_INVALID_PARAMETER;
#endif

        reportSize = 2048;
        OE_TEST(
            GetReport(options, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        ValidateReport(
            reportBuffer, reportSize, true, zeros, OE_REPORT_DATA_SIZE);

        reportSize = 2048;
        reportDataSize = 16;
        OE_TEST(
            GetReport(
                options,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, true, reportData, reportDataSize);
            OE_TEST(
                CheckReportData(
                    reportBuffer, reportSize, reportData, reportDataSize + 1) ==
                false);
        }

        reportSize = 2048;
        reportDataSize = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport(
                options,
                reportData,
                reportDataSize,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, true, reportData, reportDataSize);
        }

        reportSize = 2048;
        reportDataSize = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            GetReport(
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
            GetReport(
                options,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
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

// Expected report (quote) size for the below calls.
// This value is not expected to be same for all calls.
#if defined(OE_USE_LIBSGX)
        const uint32_t expectedReportSize = 1456;
#else
        const uint32_t expectedReportSize = 1116;
#endif
        OE_TEST(
            GetReport(options, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
        OE_TEST(reportSize == expectedReportSize);

        reportSize = 1;
        OE_TEST(
            GetReport(options, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
        OE_TEST(reportSize == expectedReportSize);
    }
}

TEST_FCN void TestParseReportNegative(void* args_)
{
    uint8_t reportBuffer[2048] = {0};
    OE_Report parsedReport = {0};

    // 1. Null report passed in.
    OE_TEST(OE_ParseReport(NULL, 0, &parsedReport) == OE_INVALID_PARAMETER);

    // 2. Report size less than size of SGX_Report.
    OE_TEST(
        OE_ParseReport(reportBuffer, sizeof(SGX_Report) - 1, &parsedReport) ==
        OE_INVALID_PARAMETER);

    // 3. Report size greater than size of SGX_Report but less than
    // sizeof(SGX_Quote)
    OE_TEST(
        OE_ParseReport(reportBuffer, sizeof(SGX_Quote) - 1, &parsedReport) ==
        OE_INVALID_PARAMETER);

    // 4. NULL parsedReport passed in.
    OE_TEST(
        OE_ParseReport(reportBuffer, sizeof(SGX_Quote), NULL) ==
        OE_INVALID_PARAMETER);
}

// Use the current enclave itself as the target enclave.
static void GetSGXTargetInfo(SGX_TargetInfo* sgxTargetInfo)
{
    SGX_Report report = {0};
    uint32_t reportSize = sizeof(SGX_Report);

    OE_TEST(
        GetReport(0, NULL, 0, NULL, 0, (uint8_t*)&report, &reportSize) ==
        OE_OK);

    Memset(sgxTargetInfo, 0, sizeof(*sgxTargetInfo));
    Memcpy(
        sgxTargetInfo->mrenclave,
        report.body.mrenclave,
        sizeof(sgxTargetInfo->mrenclave));
    Memcpy(
        &sgxTargetInfo->attributes,
        &report.body.attributes,
        sizeof(sgxTargetInfo->attributes));
    Memcpy(
        &sgxTargetInfo->misc_select,
        &report.body.miscselect,
        sizeof(sgxTargetInfo->attributes));
}

TEST_FCN void TestLocalVerifyReport(void* args_)
{
    uint8_t targetInfo[sizeof(SGX_TargetInfo)];
    uint32_t targetInfoSize = sizeof(targetInfo);
    SGX_TargetInfo* t = NULL;

    uint8_t report[sizeof(SGX_Report)] = {0};
    uint32_t reportSize = sizeof(report);

    uint8_t reportData[sizeof(SGX_ReportData)];
    for (uint32_t i = 0; i < sizeof(reportData); ++i)
    {
        reportData[i] = i;
    }

    GetSGXTargetInfo((SGX_TargetInfo*)targetInfo);

    // 1. Report with no custom report data.
    OE_TEST(
        GetReport(
            0, NULL, 0, targetInfo, targetInfoSize, report, &reportSize) ==
        OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_OK);

// 2. Report with full custom report data.
#ifdef OE_BUILD_ENCLAVE
    OE_TEST(
        GetReport(
            0,
            reportData,
            sizeof(reportData),
            targetInfo,
            targetInfoSize,
            report,
            &reportSize) == OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_OK);

    // 3. Report with partial custom report data.
    OE_TEST(
        GetReport(
            0,
            reportData,
            sizeof(reportData) / 2,
            targetInfo,
            targetInfoSize,
            report,
            &reportSize) == OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_OK);
#endif

    // 4. Negative case.

    // Change target info.
    t = (SGX_TargetInfo*)targetInfo;
    t->mrenclave[0]++;

    OE_TEST(
        GetReport(
            0, NULL, 0, targetInfo, targetInfoSize, report, &reportSize) ==
        OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_VERIFY_FAILED);
}
