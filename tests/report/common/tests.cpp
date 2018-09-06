// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/report.h>

#ifdef OE_BUILD_ENCLAVE

#define Memset oe_memset
#define Memcpy oe_memcpy
#define Memcmp oe_memcmp

#define GetReport oe_get_report

#define VerifyReport oe_verify_report

#define TEST_FCN OE_ECALL

#else

#define Memset memset
#define Memcpy memcpy
#define Memcmp memcmp

// The host side API requires the enclave to be passed in.

oe_enclave_t* g_Enclave = NULL;

#ifdef OE_BUILD_ENCLAVE
#define GetReport(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report(g_Enclave, flags, rd, rds, op, ops, rb, rbs)
#else
// Host side API does not have report_data and report_data_size
#define GetReport(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report(g_Enclave, flags, op, ops, rb, rbs)
#endif

oe_result_t VerifyReport(
    const uint8_t* report,
    size_t reportSize,
    oe_report_t* parsedReport)
{
    oe_report_t tmpReport = {0};
    OE_TEST(oe_parse_report(report, reportSize, &tmpReport) == OE_OK);

    if (tmpReport.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        // Check that remote attestation can be done entirely on the host side.
        // No enclave is passed to oe_verify_report.
        return oe_verify_report(NULL, report, reportSize, parsedReport);
    }

    // Local attestation requires enclave.
    return oe_verify_report(g_Enclave, report, reportSize, parsedReport);
}

#define TEST_FCN

#endif

#define OE_LOCAL_REPORT_SIZE (sizeof(oe_report_header_t) + sizeof(sgx_report_t))

/*
 * g_UniqueID is populated from the first call to oe_parse_report.
 * The enclave's unique_id is asserted to not change subsequently.
 */
uint8_t g_UniqueID[32];

uint8_t g_SignerID[32] = {0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
                          0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
                          0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
                          0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

uint8_t g_ProductID[16] = {0};

#ifdef OE_BUILD_ENCLAVE
static bool CheckReportData(
    uint8_t* reportBuffer,
    size_t reportSize,
    const uint8_t* report_data,
    size_t report_data_size)
{
    oe_report_t parsedReport = {0};
    OE_TEST(oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_OK);

    return (
        Memcmp(parsedReport.report_data, report_data, report_data_size) == 0);
}
#endif

static void ValidateReport(
    uint8_t* reportBuffer,
    size_t reportSize,
    bool remote,
    const uint8_t* report_data,
    size_t report_data_size)
{
    sgx_quote_t* sgxQuote = NULL;
    sgx_report_t* sgxReport = NULL;
    oe_report_header_t* header = (oe_report_header_t*)reportBuffer;

    oe_report_t parsedReport = {0};

    static bool firstTime = true;

    OE_TEST(oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_OK);

    /* Validate header. */
    OE_TEST(parsedReport.type == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(
        Memcmp(parsedReport.report_data, report_data, report_data_size) == 0);

    /* Validate pointer fields. */
    if (remote)
    {
        sgxQuote = (sgx_quote_t*)header->report;
        OE_TEST(reportSize >= sizeof(sgx_quote_t));

        OE_TEST(
            parsedReport.report_data ==
            sgxQuote->report_body.report_data.field);
        OE_TEST(parsedReport.report_data_size == sizeof(sgx_report_data_t));
        OE_TEST(
            parsedReport.enclave_report == (uint8_t*)&sgxQuote->report_body);
        OE_TEST(parsedReport.enclave_report_size == sizeof(sgx_report_body_t));
    }
    else
    {
        OE_TEST(reportSize == OE_LOCAL_REPORT_SIZE);
        sgxReport = (sgx_report_t*)header->report;

        OE_TEST(parsedReport.report_data == sgxReport->body.report_data.field);
        OE_TEST(parsedReport.report_data_size == sizeof(sgx_report_data_t));
        OE_TEST(parsedReport.enclave_report == (uint8_t*)&sgxReport->body);
        OE_TEST(parsedReport.enclave_report_size == sizeof(sgx_report_body_t));
    }

    /* Validate identity. */
    OE_TEST(parsedReport.identity.id_version == 0x0);
    OE_TEST(parsedReport.identity.security_version == 0x0);

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
            parsedReport.identity.unique_id,
            sizeof(parsedReport.identity.unique_id));

        firstTime = false;
    }

    OE_TEST(
        Memcmp(
            parsedReport.identity.unique_id,
            g_UniqueID,
            sizeof(parsedReport.identity.unique_id)) == 0);

    OE_TEST(
        Memcmp(
            parsedReport.identity.signer_id,
            g_SignerID,
            sizeof(parsedReport.identity.signer_id)) == 0);

    OE_TEST(
        Memcmp(
            parsedReport.identity.product_id,
            g_ProductID,
            sizeof(parsedReport.identity.product_id)) == 0);
}

TEST_FCN void TestLocalReport(void* args_)
{
    sgx_target_info_t* targetInfo = (sgx_target_info_t*)args_;

#ifdef OE_BUILD_ENCLAVE
    size_t report_data_size = 0;
    uint8_t report_data[OE_REPORT_DATA_SIZE];
    for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
        report_data[i] = i;
#endif

    const uint8_t zeros[OE_REPORT_DATA_SIZE] = {0};

    size_t reportSize = 1024;
    uint8_t reportBuffer[1024];

    uint8_t optParams[sizeof(sgx_target_info_t)];
    for (uint32_t i = 0; i < sizeof(optParams); ++i)
        optParams[i] = 0;

/*
 * Post conditions:
 *     1. On a successful call, the returned report size must always be
 *        sizeof(sgx_report_t);
 *     2. Report must contain specified report data or zeros as report data.
 */

/*
 * Report data parameters scenarios on enclave side:
 *      1. Report data can be NULL.
 *      2. Report data can be < OE_REPORT_DATA_SIZE
 *      3. Report data can be OE_REPORT_DATA_SIZE
 *      4. Report data cannot exceed OE_REPORT_DATA_SIZE
 *
 * Report data tests are not needed for host side.
 */
#ifdef OE_BUILD_ENCLAVE
    {
        oe_result_t expectedResult = OE_OK;
        reportSize = 1024 * 1024;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);

        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, zeros, OE_REPORT_DATA_SIZE);
        }

        reportSize = 1024 * 1024;
        report_data_size = 16;
        OE_TEST(
            GetReport(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, report_data, report_data_size);

            OE_TEST(
                CheckReportData(
                    reportBuffer,
                    reportSize,
                    report_data,
                    report_data_size + 1) == false);
        }

        reportSize = 1024 * 1024;
        report_data_size = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);

        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, false, report_data, report_data_size);
        }

        reportSize = 1024 * 1024;
        report_data_size = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            GetReport(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
    }
#endif // End of report_data scenarios

    /*
     * optParams scenarios:
     *     1. If optParams is not null, optParamsSize must be
     * sizeof(sgx_target_info_t)
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
                sizeof(sgx_target_info_t),
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(reportSize == OE_LOCAL_REPORT_SIZE);
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
        OE_TEST(reportSize == OE_LOCAL_REPORT_SIZE);
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
        OE_TEST(reportSize == OE_LOCAL_REPORT_SIZE);

        reportSize = 1;
        OE_TEST(
            GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);
        OE_TEST(reportSize == OE_LOCAL_REPORT_SIZE);
    }
}

TEST_FCN void TestRemoteReport(void* args_)
{
#ifdef OE_BUILD_ENCLAVE
    size_t report_data_size = 0;
    uint8_t report_data[OE_REPORT_DATA_SIZE];
    for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
        report_data[i] = i;
    const uint8_t zeros[OE_REPORT_DATA_SIZE] = {0};
#endif

    uint8_t reportBuffer[OE_MAX_REPORT_SIZE];
    size_t reportSize = sizeof(reportBuffer);

    uint8_t optParams[sizeof(sgx_target_info_t)];
    for (uint32_t i = 0; i < sizeof(optParams); ++i)
        optParams[i] = 0;

    uint32_t flags = OE_REPORT_OPTIONS_REMOTE_ATTESTATION;
/*
 * Post conditions:
 *     1. Report must contain specified report data or zeros as report data.
 */

/*
 * Report data parameters scenarios on enclave side:
 *      a. Report data can be NULL.
 *      b. Report data can be < OE_REPORT_DATA_SIZE
 *      c. Report data can be OE_REPORT_DATA_SIZE
 *      d. Report data cannot exceed OE_REPORT_DATA_SIZE
 *
 * Report data is not a parameter on the host side.
 */
#ifdef OE_BUILD_ENCLAVE
    {
        oe_result_t expectedResult = OE_OK;
        reportSize = sizeof(reportBuffer);
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        ValidateReport(
            reportBuffer, reportSize, true, zeros, OE_REPORT_DATA_SIZE);

        reportSize = sizeof(reportBuffer);
        report_data_size = 16;
        OE_TEST(
            GetReport(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, true, report_data, report_data_size);
            OE_TEST(
                CheckReportData(
                    reportBuffer,
                    reportSize,
                    report_data,
                    report_data_size + 1) == false);
        }

        reportSize = sizeof(reportBuffer);
        report_data_size = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == expectedResult);
        if (expectedResult == OE_OK)
        {
            ValidateReport(
                reportBuffer, reportSize, true, report_data, report_data_size);
        }

        reportSize = sizeof(reportBuffer);
        report_data_size = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            GetReport(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
    }
#endif

    /*
     * optParams scenarios:
     *     1. Both optParams and optParamsSize must be NULL/0.
     */
    {
        reportSize = sizeof(reportBuffer);
        OE_TEST(
            GetReport(
                flags,
                NULL,
                0,
                NULL,
                sizeof(optParams),
                reportBuffer,
                &reportSize) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
                flags, NULL, 0, optParams, 5, reportBuffer, &reportSize) ==
            OE_INVALID_PARAMETER);
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     *     b. Size too small.
     */
    {
        reportSize = sizeof(reportBuffer);

        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, NULL, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        // Assert that with the returned reportSize buffer can be created.
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);

        reportSize = 1;
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_BUFFER_TOO_SMALL);

        // Assert that with the returned reportSize buffer can be created.
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
    }
}

TEST_FCN void TestParseReportNegative(void* args_)
{
    uint8_t reportBuffer[OE_MAX_REPORT_SIZE] = {0};
    oe_report_t parsedReport = {0};

    // 1. Null report passed in.
    OE_TEST(oe_parse_report(NULL, 0, &parsedReport) == OE_INVALID_PARAMETER);

    // 2. Report size less than size of sgx_report_t.
    OE_TEST(
        oe_parse_report(
            reportBuffer, sizeof(sgx_report_t) - 1, &parsedReport) ==
        OE_INVALID_PARAMETER);

    // 3. Report size greater than size of sgx_report_t but less than
    // sizeof(sgx_quote_t)
    OE_TEST(
        oe_parse_report(reportBuffer, sizeof(sgx_quote_t) - 1, &parsedReport) ==
        OE_INVALID_PARAMETER);

    // 4. NULL parsedReport passed in.
    OE_TEST(
        oe_parse_report(reportBuffer, sizeof(sgx_quote_t), NULL) ==
        OE_INVALID_PARAMETER);

    // Get a valid report and tweak fields.
    size_t reportSize = OE_MAX_REPORT_SIZE;
    OE_TEST(GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);
    OE_TEST(oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_OK);

    oe_report_header_t* header = (oe_report_header_t*)reportBuffer;

    // 5. Header's version is invalid.
    header->version++;
    OE_TEST(
        oe_parse_report(reportBuffer, reportSize, &parsedReport) ==
        OE_INVALID_PARAMETER);
    header->version--;
    OE_TEST(oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_OK);

    // 6. Header's report_size is invalid.
    // ie: report_size + sizeof(oe_report_header_t) != reportSize
    header->report_size++;
    OE_TEST(
        oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_FAILURE);
    header->report_size--;
    OE_TEST(oe_parse_report(reportBuffer, reportSize, &parsedReport) == OE_OK);

    // 7. Header's report_type is invalid.
    header->report_type = (oe_report_type_t)20;
    OE_TEST(
        oe_parse_report(reportBuffer, reportSize, &parsedReport) ==
        OE_REPORT_PARSE_ERROR);
}

// Use the current enclave itself as the target enclave.
static void GetSGXTargetInfo(sgx_target_info_t* sgxTargetInfo)
{
    uint8_t reportBuffer[OE_LOCAL_REPORT_SIZE];
    size_t reportSize = sizeof(reportBuffer);

    oe_report_header_t* header = (oe_report_header_t*)reportBuffer;
    sgx_report_t* sgxReport = (sgx_report_t*)header->report;

    OE_TEST(GetReport(0, NULL, 0, NULL, 0, reportBuffer, &reportSize) == OE_OK);

    Memset(sgxTargetInfo, 0, sizeof(*sgxTargetInfo));
    Memcpy(
        sgxTargetInfo->mrenclave,
        &sgxReport->body.mrenclave,
        sizeof(sgxTargetInfo->mrenclave));
    Memcpy(
        &sgxTargetInfo->attributes,
        &sgxReport->body.attributes,
        sizeof(sgxTargetInfo->attributes));
    Memcpy(
        &sgxTargetInfo->misc_select,
        &sgxReport->body.miscselect,
        sizeof(sgxTargetInfo->attributes));
}

TEST_FCN void TestLocalVerifyReport(void* args_)
{
    uint8_t targetInfo[sizeof(sgx_target_info_t)];
    size_t targetInfoSize = sizeof(targetInfo);

    uint8_t report[OE_LOCAL_REPORT_SIZE] = {0};
    size_t reportSize = sizeof(report);
    sgx_target_info_t* tamperedTargetInfo = NULL;

    uint8_t report_data[sizeof(sgx_report_data_t)];
    for (uint32_t i = 0; i < sizeof(report_data); ++i)
    {
        report_data[i] = i;
    }

    GetSGXTargetInfo((sgx_target_info_t*)targetInfo);

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
            report_data,
            sizeof(report_data),
            targetInfo,
            targetInfoSize,
            report,
            &reportSize) == OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_OK);

    // 3. Report with partial custom report data.
    OE_TEST(
        GetReport(
            0,
            report_data,
            sizeof(report_data) / 2,
            targetInfo,
            targetInfoSize,
            report,
            &reportSize) == OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_OK);
#endif

    // 4. Negative case.

    // Tamper with the target info.
    tamperedTargetInfo = (sgx_target_info_t*)targetInfo;
    tamperedTargetInfo->mrenclave[0]++;

    OE_TEST(
        GetReport(
            0, NULL, 0, targetInfo, targetInfoSize, report, &reportSize) ==
        OE_OK);
    OE_TEST(VerifyReport(report, reportSize, NULL) == OE_VERIFY_FAILED);
}

TEST_FCN void TestRemoteVerifyReport(void* args_)
{
    uint8_t reportBuffer[OE_MAX_REPORT_SIZE] = {0};
    size_t reportSize = sizeof(reportBuffer);

#if OE_BUILD_ENCLAVE
    uint8_t report_data[sizeof(sgx_report_data_t)];
    size_t report_data_size = sizeof(report_data);

    for (uint32_t i = 0; i < sizeof(report_data); ++i)
    {
        report_data[i] = i;
    }
#endif

    uint32_t flags = OE_REPORT_OPTIONS_REMOTE_ATTESTATION;

    /*
     * Report data parameters scenarios on enclave side:
     *      a. Report data can be NULL.
     *      b. Report data can be < OE_REPORT_DATA_SIZE
     *      c. Report data can be OE_REPORT_DATA_SIZE
     * On host side, report data is not a valid parameter
     */
    {
        reportSize = sizeof(reportBuffer);
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, reportBuffer, &reportSize) ==
            OE_OK);
        OE_TEST(VerifyReport(reportBuffer, reportSize, NULL) == OE_OK);

#if OE_BUILD_ENCLAVE
        reportSize = sizeof(reportBuffer);
        report_data_size = 16;
        OE_TEST(
            GetReport(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(VerifyReport(reportBuffer, reportSize, NULL) == OE_OK);

        reportSize = sizeof(reportBuffer);
        report_data_size = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                reportBuffer,
                &reportSize) == OE_OK);
        OE_TEST(VerifyReport(reportBuffer, reportSize, NULL) == OE_OK);
#endif
    }
}
