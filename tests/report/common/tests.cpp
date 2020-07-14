// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../common/tests.h"
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>

#ifndef OE_BUILD_ENCLAVE
#include "../../../host/sgx/sgxquoteprovider.h"
#endif
#include "../../../common/oe_host_stdlib.h"
#include "../../../common/sgx/collateral.h"
#include "../../../common/sgx/endorsements.h"
#include "../../../common/sgx/qeidentity.h"
#include "../../../common/sgx/quote.h"

#include <time.h>
#include <array>

using namespace std;

/**
 * Get collateral data which can be used with future function
 * oe_verify_report_with_collaterals().
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] collaterals_buffer The buffer containing the collaterals to parse.
 * @param[in] collaterals_buffer_size The size of the **collaterals_buffer**.
 *
 * @retval OE_OK The collaterals were successfully retrieved.
 */
oe_result_t oe_get_collaterals(
#ifndef OE_BUILD_ENCLAVE
    oe_enclave_t* enclave,
#endif
    uint8_t** collaterals_buffer,
    size_t* collaterals_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_t* parsed_report = NULL;
    oe_report_header_t* header = NULL;

    OE_TRACE_INFO("Enter enclave call %s\n", __FUNCTION__);

    if ((collaterals_buffer == NULL) || (collaterals_buffer_size == NULL))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    *collaterals_buffer = NULL;
    *collaterals_buffer_size = 0;

#ifdef OE_BUILD_ENCLAVE
    // Get a remote OE report.
    // We need a report in order to fetch the uris of the certificates in the
    // sgx quote.
    OE_CHECK_MSG(
        oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            (uint8_t**)&remote_report,
            &report_size),
        "Failed to get OE remote report. %s",
        oe_result_str(result));
    header = (oe_report_header_t*)remote_report;

    OE_CHECK_MSG(
        oe_verify_report(remote_report, report_size, parsed_report),
        "Failed to verify OE remote report. %s",
        oe_result_str(result));
#else
    OE_CHECK_MSG(
        oe_initialize_quote_provider(),
        "Failed to initialize quote provider. %s",
        oe_result_str(result));

    OE_CHECK_MSG(
        oe_get_report(
            enclave,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            (uint8_t**)&remote_report,
            &report_size),
        "Failed to get OE remote report. %s",
        oe_result_str(result));
    header = (oe_report_header_t*)remote_report;

    OE_CHECK_MSG(
        oe_verify_report(enclave, remote_report, report_size, parsed_report),
        "Failed to verify OE remote report. %s",
        oe_result_str(result));
#endif

    OE_CHECK_MSG(
        oe_get_sgx_endorsements(
            header->report,
            header->report_size,
            collaterals_buffer,
            collaterals_buffer_size),
        "Failed to get collaterals. %s",
        oe_result_str(result));

    result = OE_OK;
done:
    if (remote_report)
        oe_free_report(remote_report);

    OE_TRACE_INFO(
        "Exit enclave call %s: %d(%s)\n",
        __FUNCTION__,
        result,
        oe_result_str(result));

    return result;
}

/**
 * Verify the integrity of the report and its signature,
 * with optional collateral data that is associated with the report.
 *
 * This function verifies that the report signature is valid. This only applies
 * to remote reports.  For remote reports it verifies that the signing authority
 * is rooted to a trusted authority such as the enclave platform manufacturer.
 *
 * @param[in] enclave The instance of the enclave that will be used.
 * @param[in] report The buffer containing the report to verify.
 * @param[in] report_size The size of the **report** buffer.
 * @param[in] collaterals Optional The collateral data that is associated with
 * the report.
 * @param[in] collaterals_size The size of the **collaterals** buffer.
 * @param[in] input_validation_time Optional datetime to use when validating
 * collaterals. If not specified, it will used the creation_datetime of the
 * collaterals (if any collaterals are provided).
 * @param[out] parsed_report Optional **oe_report_t** structure to populate with
 * the report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
static oe_result_t oe_verify_report_with_collaterals(
#ifndef OE_BUILD_ENCLAVE
    oe_enclave_t* enclave,
#endif
    const uint8_t* report,
    size_t report_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* input_validation_time,
    oe_report_t* parsed_report)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;

    if (report == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
#ifndef OE_BUILD_ENCLAVE
        // Intialize the quote provider if we want to verify a remote quote.
        // Note that we don't have the OE_HAS_SGX_DCAP_QL guard here since we
        // don't need the sgx libraries to verify the quote. All we need is the
        // quote provider.
        OE_CHECK(oe_initialize_quote_provider());
#endif

        // Quote attestation can be done entirely on the host side.
        OE_CHECK(oe_verify_sgx_quote(
            header->report,
            header->report_size,
            collaterals,
            collaterals_size,
            input_validation_time));

        // Optionally return parsed report.
        if (parsed_report != NULL)
            OE_CHECK(oe_parse_report(report, report_size, parsed_report));
    }
    else if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
    {
        if (collaterals != NULL || collaterals_size > 0)
        {
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "Local reports should not have collaterals.",
                NULL);
        }

#ifndef OE_BUILD_ENCLAVE
        if (enclave == NULL)
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_CHECK(oe_verify_report(enclave, report, report_size, parsed_report));
#else
        OE_CHECK(oe_verify_report(report, report_size, parsed_report));
#endif
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    result = OE_OK;
done:
    return result;
}

/**
 * Free up any resources allocated by oe_get_collateras()
 *
 * @param[in] collaterals_buffer The buffer containing the collaterals.
 */
static void oe_free_collaterals(uint8_t* collaterals_buffer)
{
    oe_free_sgx_endorsements(collaterals_buffer);
}

/*!
 * Find the valid datetime range for the given **remote report** and
 * collaterals. This function accounts for the following items:
 *
 * 1. From the quote:
 *          a) Root CA.
 *          b) Intermediate CA.
 *          b) PCK CA.
 * 2. From the revocation info:
 *          a) Root CA CRL.
 *          b) Intermediate CA CRL.
 *          c) PCK CA CRL.
 *          d) TCB info cert.
 *          e) TCB info.
 * 3. From QE identity info
 *          a) QE identity cert.
 *          b) QE identity.
 *
 * @param[in] report The buffer containing the report to verify.
 * @param[in] report_size The size of the **report** buffer.
 * @param[in] endorsements Endorsements related to the quote.
 * @param[in] endorsements_size The size of the endorsements.
 * @param[out] valid_from validity_from The date from which the quote is valid.
 * @param[out] valid_until validity_until The date which the quote expires.
 */
static oe_result_t oe_get_quote_validity_with_collaterals(
    const uint8_t* report,
    const size_t report_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_report_t oe_report = {0};
    oe_report_header_t* header = (oe_report_header_t*)report;
    oe_sgx_endorsements_t sgx_endorsements;

    if (report == NULL || endorsements == NULL || valid_from == NULL ||
        valid_until == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (report_size == 0 || report_size > OE_MAX_REPORT_SIZE ||
        endorsements_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that the report is parseable before using the header.
    OE_CHECK(oe_parse_report(report, report_size, &oe_report));

    if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
    {
#ifndef OE_BUILD_ENCLAVE
        // Intialize the quote provider if we want to verify a remote quote.
        // Note that we don't have the OE_HAS_SGX_DCAP_QL guard here since we
        // don't need the sgx libraries to verify the quote. All we need is the
        // quote provider.
        OE_CHECK(oe_initialize_quote_provider());
#endif

        OE_CHECK_MSG(
            oe_parse_sgx_endorsements(
                (oe_endorsements_t*)endorsements,
                endorsements_size,
                &sgx_endorsements),
            "Failed to parse SGX endorsements.",
            oe_result_str(result));

        // Quote attestation can be done entirely on the host side.
        OE_CHECK(oe_get_sgx_quote_validity(
            header->report,
            header->report_size,
            &sgx_endorsements,
            valid_from,
            valid_until));
    }
    else
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    result = OE_OK;
done:
    return result;
}

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/corelibc/string.h>

#define GetReport oe_get_report
#define GetReport_v2 oe_get_report_v2

#define GetCollaterals oe_get_collaterals

#define VerifyReport oe_verify_report
#define VerifyReportWithCollaterals oe_verify_report_with_collaterals
#define GetQuoteValidityWithCollaterals oe_get_quote_validity_with_collaterals

#else

// The host side API requires the enclave to be passed in.

oe_enclave_t* g_enclave = NULL;

// Host side API does not have report_data and report_data_size
#define GetReport(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report(g_enclave, flags, op, ops, rb, rbs)
#define GetReport_v2(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report_v2(g_enclave, flags, op, ops, rb, rbs)

// Get collateral macros.  Host side API has an additional enclave object.
#define GetCollaterals(data, data_size) \
    oe_get_collaterals(g_enclave, data, data_size)

oe_result_t VerifyReport(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report)
{
    oe_report_t tmp_report = {0};
    OE_TEST(oe_parse_report(report, report_size, &tmp_report) == OE_OK);

    if (tmp_report.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        // Check that remote attestation can be done entirely on the host side.
        // No enclave is passed to oe_verify_report.
        return oe_verify_report(NULL, report, report_size, parsed_report);
    }

    // Local attestation requires enclave.
    return oe_verify_report(g_enclave, report, report_size, parsed_report);
}

oe_result_t VerifyReportWithCollaterals(
    const uint8_t* report,
    size_t report_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* input_validation_time,
    oe_report_t* parsed_report)
{
    oe_report_t tmp_report = {0};
    OE_TEST(oe_parse_report(report, report_size, &tmp_report) == OE_OK);

    if (tmp_report.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        return oe_verify_report_with_collaterals(
            g_enclave,
            report,
            report_size,
            collaterals,
            collaterals_size,
            input_validation_time,
            parsed_report);
    }
    else
    {
        return OE_UNSUPPORTED;
    }
}

oe_result_t GetQuoteValidityWithCollaterals(
    const uint8_t* report,
    size_t report_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* valid_from,
    oe_datetime_t* valid_until)
{
    oe_report_t tmp_report = {0};
    OE_TEST(oe_parse_report(report, report_size, &tmp_report) == OE_OK);

    if (tmp_report.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE)
    {
        return oe_get_quote_validity_with_collaterals(
            report,
            report_size,
            collaterals,
            collaterals_size,
            valid_from,
            valid_until);
    }
    else
    {
        return OE_UNSUPPORTED;
    }
}

#endif

#define OE_LOCAL_REPORT_SIZE (sizeof(oe_report_header_t) + sizeof(sgx_report_t))

/*
 * g_unique_id is populated from the first call to oe_parse_report.
 * The enclave's unique_id is asserted to not change subsequently.
 */
uint8_t g_unique_id[32];

uint8_t g_signer_id[32] = {0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a,
                           0xa2, 0x88, 0x90, 0xce, 0x73, 0xe4, 0x33, 0x63,
                           0x83, 0x77, 0xf1, 0x79, 0xab, 0x44, 0x56, 0xb2,
                           0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

uint8_t g_product_id[16] = {0};

#ifdef OE_BUILD_ENCLAVE
static bool CheckReportData(
    uint8_t* report_buffer,
    size_t report_size,
    const uint8_t* report_data,
    size_t report_data_size)
{
    oe_report_t parsed_report = {0};
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) == OE_OK);

    return (
        memcmp(parsed_report.report_data, report_data, report_data_size) == 0);
}
#endif

static void ValidateReport(
    uint8_t* report_buffer,
    size_t report_size,
    bool remote,
    const uint8_t* report_data,
    size_t report_data_size)
{
    sgx_quote_t* sgx_quote = NULL;
    sgx_report_t* sgx_report = NULL;
    oe_report_header_t* header = (oe_report_header_t*)report_buffer;

    oe_report_t parsed_report = {0};

    static bool first_time = true;

    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) == OE_OK);

    /* Validate header. */
    OE_TEST(parsed_report.type == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(
        memcmp(parsed_report.report_data, report_data, report_data_size) == 0);

    /* Validate pointer fields. */
    if (remote)
    {
        sgx_quote = (sgx_quote_t*)header->report;
        OE_TEST(report_size >= sizeof(sgx_quote_t));

        OE_TEST(
            parsed_report.report_data ==
            sgx_quote->report_body.report_data.field);
        OE_TEST(parsed_report.report_data_size == sizeof(sgx_report_data_t));
        OE_TEST(
            parsed_report.enclave_report == (uint8_t*)&sgx_quote->report_body);
        OE_TEST(parsed_report.enclave_report_size == sizeof(sgx_report_body_t));
    }
    else
    {
        OE_TEST(report_size == OE_LOCAL_REPORT_SIZE);
        sgx_report = (sgx_report_t*)header->report;

        OE_TEST(
            parsed_report.report_data == sgx_report->body.report_data.field);
        OE_TEST(parsed_report.report_data_size == sizeof(sgx_report_data_t));
        OE_TEST(parsed_report.enclave_report == (uint8_t*)&sgx_report->body);
        OE_TEST(parsed_report.enclave_report_size == sizeof(sgx_report_body_t));
    }

    /* Validate identity. */
    OE_TEST(parsed_report.identity.id_version == 0x0);
    OE_TEST(parsed_report.identity.security_version == 0x0);

    OE_TEST(parsed_report.identity.attributes & OE_REPORT_ATTRIBUTES_DEBUG);

    OE_TEST(
        !(parsed_report.identity.attributes & OE_REPORT_ATTRIBUTES_RESERVED));

    OE_TEST(
        (bool)(parsed_report.identity.attributes & OE_REPORT_ATTRIBUTES_REMOTE) ==
        remote);

    if (first_time)
    {
        memcpy(
            g_unique_id,
            parsed_report.identity.unique_id,
            sizeof(parsed_report.identity.unique_id));

        first_time = false;
    }

    OE_TEST(
        memcmp(
            parsed_report.identity.unique_id,
            g_unique_id,
            sizeof(parsed_report.identity.unique_id)) == 0);

    OE_TEST(
        memcmp(
            parsed_report.identity.signer_id,
            g_signer_id,
            sizeof(parsed_report.identity.signer_id)) == 0);

    OE_TEST(
        memcmp(
            parsed_report.identity.product_id,
            g_product_id,
            sizeof(parsed_report.identity.product_id)) == 0);
}

void test_local_report(sgx_target_info_t* target_info)
{
    const uint8_t zeros[OE_REPORT_DATA_SIZE] = {0};

    size_t report_ptr_size;
    uint8_t* report_buffer_ptr;

    uint8_t opt_params[sizeof(sgx_target_info_t)];
    for (uint32_t i = 0; i < sizeof(opt_params); ++i)
        opt_params[i] = 0;

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
        size_t report_data_size = 0;
        uint8_t report_data[OE_REPORT_DATA_SIZE];
        for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
            report_data[i] = static_cast<uint8_t>(i);
        oe_result_t expected_result = OE_OK;

        OE_TEST(
            GetReport_v2(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size) ==
            OE_OK);

        if (expected_result == OE_OK)
        {
            ValidateReport(
                report_buffer_ptr,
                report_ptr_size,
                false,
                zeros,
                OE_REPORT_DATA_SIZE);
        }
        oe_free_report(report_buffer_ptr);

        OE_TEST(
            GetReport(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size) ==
            OE_OK);

        if (expected_result == OE_OK)
        {
            ValidateReport(
                report_buffer_ptr,
                report_ptr_size,
                false,
                zeros,
                OE_REPORT_DATA_SIZE);
        }
        oe_free_report(report_buffer_ptr);

        report_data_size = 16;
        OE_TEST(
            GetReport_v2(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == expected_result);
        if (expected_result == OE_OK)
        {
            ValidateReport(
                report_buffer_ptr,
                report_ptr_size,
                false,
                report_data,
                report_data_size);

            OE_TEST(
                CheckReportData(
                    report_buffer_ptr,
                    report_ptr_size,
                    report_data,
                    report_data_size + 1) == false);
            oe_free_report(report_buffer_ptr);
        }

        report_data_size = OE_REPORT_DATA_SIZE;
        OE_TEST(
            GetReport_v2(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == expected_result);

        if (expected_result == OE_OK)
        {
            ValidateReport(
                report_buffer_ptr,
                report_ptr_size,
                false,
                report_data,
                report_data_size);

            oe_free_report(report_buffer_ptr);
        }

        report_data_size = OE_REPORT_DATA_SIZE + 1;
        OE_TEST(
            GetReport_v2(
                0,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
    }
#endif // End of report_data scenarios

    /*
     * opt_params scenarios:
     *     1. If opt_params is not null, opt_params_size must be
     * sizeof(sgx_target_info_t)
     *     2. Otherwise, both must be null/0.
     *     3. opt_params can be zeroed out target info.
     *     4. opt_params can be a valid target info.
     */
    {
        OE_TEST_CODE(
            GetReport_v2(
                0,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_INVALID_PARAMETER);
        OE_TEST_CODE(
            GetReport(
                0,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_INVALID_PARAMETER);
    }

    {
        OE_TEST_CODE(
            GetReport_v2(
                0,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size),
            OE_INVALID_PARAMETER);
        OE_TEST_CODE(
            GetReport(
                0,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size),
            OE_INVALID_PARAMETER);

        OE_TEST_CODE(
            GetReport_v2(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size),
            OE_OK);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
        OE_TEST_CODE(
            GetReport(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size),
            OE_OK);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
    }

    {
        OE_TEST_CODE(
            GetReport_v2(
                0,
                NULL,
                0,
                opt_params,
                sizeof(sgx_target_info_t),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;

        OE_TEST_CODE(
            GetReport(
                0,
                NULL,
                0,
                opt_params,
                sizeof(sgx_target_info_t),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
    }

    {
        OE_TEST_CODE(
            GetReport_v2(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);

        OE_TEST_CODE(
            GetReport(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
    }

    /* oe_get_target_info scenario.
     *   a. Extract the target_info from the report and use that
     *      as the opt_params field.
     *   b. Ensure oe_get_target_info fails on improper inputs.
     */
    {
        sgx_target_info_t target;
        sgx_target_info_t* target_ptr;
        size_t target_ptr_size = 0;

        OE_TEST_CODE(
            GetReport_v2(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size),
            OE_OK);

        OE_TEST_CODE(
            oe_get_target_info_v2(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                &target_ptr_size),
            OE_OK);
        OE_TEST(target_ptr_size == sizeof(target));
        oe_free_target_info(target_ptr);

        target_ptr = NULL;
        target_ptr_size = 0;
        OE_TEST_CODE(
            oe_get_target_info(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                &target_ptr_size),
            OE_OK);
        OE_TEST(target_ptr_size == sizeof(target));
        oe_free_target_info(target_ptr);

        /* Failure cases. */
        OE_TEST_CODE(
            oe_get_target_info_v2(
                NULL, report_ptr_size, (void**)&target_ptr, &target_ptr_size),
            OE_INVALID_PARAMETER);
        OE_TEST_CODE(
            oe_get_target_info(
                NULL, report_ptr_size, (void**)&target_ptr, &target_ptr_size),
            OE_INVALID_PARAMETER);

        OE_TEST_CODE(
            oe_get_target_info_v2(
                report_buffer_ptr,
                sizeof(oe_report_header_t) + sizeof(sgx_report_t) - 1,
                (void**)&target_ptr,
                &target_ptr_size),
            OE_INVALID_PARAMETER);
        OE_TEST_CODE(
            oe_get_target_info(
                report_buffer_ptr,
                sizeof(oe_report_header_t) + sizeof(sgx_report_t) - 1,
                (void**)&target_ptr,
                &target_ptr_size),
            OE_INVALID_PARAMETER);

        OE_TEST_CODE(
            oe_get_target_info_v2(
                report_buffer_ptr, report_ptr_size, (void**)&target_ptr, NULL),
            OE_INVALID_PARAMETER);
        OE_TEST_CODE(
            oe_get_target_info_v2(
                report_buffer_ptr, report_ptr_size, (void**)&target_ptr, NULL),
            OE_INVALID_PARAMETER);

        oe_free_report(report_buffer_ptr);
    }
}

void test_remote_report()
{
#ifdef OE_BUILD_ENCLAVE
    size_t report_data_size = 0;
    uint8_t report_data[OE_REPORT_DATA_SIZE];
    for (uint32_t i = 0; i < OE_REPORT_DATA_SIZE; ++i)
        report_data[i] = static_cast<uint8_t>(i);
#endif

    uint8_t* report_buffer_ptr;
    size_t report_ptr_size;

    uint8_t opt_params[sizeof(sgx_target_info_t)];
    for (uint32_t i = 0; i < sizeof(opt_params); ++i)
        opt_params[i] = 0;

    uint32_t flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

/*
 * Post conditions:
 *     1. Report must contain specified report data or zeros as report data.
 */
#ifdef OE_BUILD_ENCLAVE
    {
        oe_result_t expected_result = OE_OK;
        report_data_size = 16;
        OE_TEST(
            GetReport_v2(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == expected_result);
        if (expected_result == OE_OK)
        {
            ValidateReport(
                report_buffer_ptr,
                report_ptr_size,
                true,
                report_data,
                report_data_size);
            OE_TEST(
                CheckReportData(
                    report_buffer_ptr,
                    report_ptr_size,
                    report_data,
                    report_data_size + 1) == false);
            oe_free_report(report_buffer_ptr);
        }
    }
#endif

    /*
     * opt_params scenarios:
     *     1. Both opt_params and opt_params_size must be NULL/0.
     */
    {
        OE_TEST(
            GetReport_v2(
                flags,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
                flags,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport_v2(
                flags,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
                flags,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
    }

    /*
     * OE_SMALL_BUFFER scenarios:
     *     a. NULL buffer
     */
    {
        OE_TEST(
            GetReport_v2(flags, NULL, 0, NULL, 0, NULL, &report_ptr_size) ==
            OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(flags, NULL, 0, NULL, 0, NULL, &report_ptr_size) ==
            OE_INVALID_PARAMETER);

        // Assert that with the returned report_size buffer can be created.
        report_buffer_ptr = NULL;
        OE_TEST(
            GetReport(
                flags,
                NULL,
                0,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
        OE_TEST(
            GetReport(
                flags,
                NULL,
                0,
                NULL,
                0,
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
    }
}

void test_parse_report_negative()
{
    uint8_t* report_buffer = NULL;
    oe_report_t parsed_report = {0};

    // 1. Null report passed in.
    OE_TEST(oe_parse_report(NULL, 0, &parsed_report) == OE_INVALID_PARAMETER);

    // 2. Report size less than size of sgx_report_t.
    OE_TEST(
        oe_parse_report(
            report_buffer, sizeof(sgx_report_t) - 1, &parsed_report) ==
        OE_INVALID_PARAMETER);

    // 3. Report size greater than size of sgx_report_t but less than
    // sizeof(sgx_quote_t)
    OE_TEST(
        oe_parse_report(
            report_buffer, sizeof(sgx_quote_t) - 1, &parsed_report) ==
        OE_INVALID_PARAMETER);

    // 4. NULL parsed_report passed in.
    OE_TEST(
        oe_parse_report(report_buffer, sizeof(sgx_quote_t), NULL) ==
        OE_INVALID_PARAMETER);

    // Get a valid report and tweak fields.
    size_t report_size = OE_MAX_REPORT_SIZE;
    OE_TEST(
        GetReport_v2(0, NULL, 0, NULL, 0, &report_buffer, &report_size) ==
        OE_OK);
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) == OE_OK);

    oe_report_header_t* header = (oe_report_header_t*)report_buffer;

    // 5. Header's version is invalid.
    header->version++;
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) ==
        OE_INVALID_PARAMETER);
    header->version--;
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) == OE_OK);

    // 6. Header's report_size is invalid.
    // ie: report_size + sizeof(oe_report_header_t) != report_size
    header->report_size++;
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) ==
        OE_INCORRECT_REPORT_SIZE);
    header->report_size--;
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) == OE_OK);

    // 7. Header's report_type is invalid.
    header->report_type = (oe_report_type_t)20;
    OE_TEST(
        oe_parse_report(report_buffer, report_size, &parsed_report) ==
        OE_REPORT_PARSE_ERROR);

    oe_free_report(report_buffer);
}

// Use the current enclave itself as the target enclave.
static void GetSGXTargetInfo(sgx_target_info_t* sgx_target_info)
{
    uint8_t* report_buffer;
    size_t report_size = sizeof(report_buffer);

    OE_TEST(
        GetReport_v2(0, NULL, 0, NULL, 0, &report_buffer, &report_size) ==
        OE_OK);

    oe_report_header_t* header = (oe_report_header_t*)report_buffer;
    sgx_report_t* sgx_report = (sgx_report_t*)header->report;

    memset(sgx_target_info, 0, sizeof(*sgx_target_info));
    memcpy(
        sgx_target_info->mrenclave,
        &sgx_report->body.mrenclave,
        sizeof(sgx_target_info->mrenclave));
    memcpy(
        &sgx_target_info->attributes,
        &sgx_report->body.attributes,
        sizeof(sgx_target_info->attributes));
    memcpy(
        &sgx_target_info->misc_select,
        &sgx_report->body.miscselect,
        sizeof(sgx_target_info->attributes));

    oe_free_report(report_buffer);
}

void test_local_verify_report()
{
    uint8_t target_info[sizeof(sgx_target_info_t)];
    size_t target_info_size = sizeof(target_info);

    uint8_t* report_ptr;
    size_t report_size;
    sgx_target_info_t* tampered_target_info = NULL;

    uint8_t report_data[sizeof(sgx_report_data_t)];
    for (uint32_t i = 0; i < sizeof(report_data); ++i)
    {
        report_data[i] = static_cast<uint8_t>(i);
    }

    GetSGXTargetInfo((sgx_target_info_t*)target_info);

    // 1. Report with no custom report data.
    OE_TEST_CODE(
        GetReport_v2(
            0,
            NULL,
            0,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size),
        OE_OK);
    OE_TEST_CODE(VerifyReport(report_ptr, report_size, NULL), OE_OK);
    oe_free_report(report_ptr);

// 2. Report with full custom report data.
#ifdef OE_BUILD_ENCLAVE
    OE_TEST_CODE(
        GetReport_v2(
            0,
            report_data,
            sizeof(report_data),
            target_info,
            target_info_size,
            &report_ptr,
            &report_size),
        OE_OK);
    OE_TEST_CODE(VerifyReport(report_ptr, report_size, NULL), OE_OK);
    oe_free_report(report_ptr);

    // 3. Report with partial custom report data.
    OE_TEST_CODE(
        GetReport_v2(
            0,
            report_data,
            sizeof(report_data) / 2,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size),
        OE_OK);
    OE_TEST_CODE(VerifyReport(report_ptr, report_size, NULL), OE_OK);
    oe_free_report(report_ptr);
#endif

    // 4. Negative case.

    // Tamper with the target info.
    tampered_target_info = (sgx_target_info_t*)target_info;
    tampered_target_info->mrenclave[0]++;

    OE_TEST_CODE(
        GetReport_v2(
            0,
            NULL,
            0,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size),
        OE_OK);
    OE_TEST_CODE(
        VerifyReport(report_ptr, report_size, NULL),
        OE_VERIFY_FAILED_AES_CMAC_MISMATCH);
    oe_free_report(report_ptr);
}

void test_remote_verify_report()
{
    uint8_t* report_ptr;
    size_t report_size;

#ifdef OE_BUILD_ENCLAVE
    uint8_t report_data[sizeof(sgx_report_data_t)];
    size_t report_data_size = sizeof(report_data);

    for (uint32_t i = 0; i < sizeof(report_data); ++i)
    {
        report_data[i] = static_cast<uint8_t>(i);
    }
#endif

    uint32_t flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

    /*
     * Report data parameters scenarios on enclave side:
     *      a. Report data can be NULL.
     *      b. Report data can be < OE_REPORT_DATA_SIZE
     *      c. Report data can be OE_REPORT_DATA_SIZE
     * On host side, report data is not a valid parameter
     */
    {
        OE_TEST_CODE(
            GetReport_v2(flags, NULL, 0, NULL, 0, &report_ptr, &report_size),
            OE_OK);
        OE_TEST_CODE(VerifyReport(report_ptr, report_size, NULL), OE_OK);
        oe_free_report(report_ptr);

#ifdef OE_BUILD_ENCLAVE
        report_data_size = 16;
        OE_TEST_CODE(
            GetReport_v2(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_ptr,
                &report_size),
            OE_OK);
        OE_TEST_CODE(VerifyReport(report_ptr, report_size, NULL), OE_OK);
        oe_free_report(report_ptr);
#endif
    }
}

void test_verify_report_with_collaterals()
{
    uint32_t flags = OE_REPORT_FLAGS_REMOTE_ATTESTATION;

    size_t report_ptr_size;
    uint8_t* report_buffer_ptr;

    size_t collaterals_ptr_size = 0;
    uint8_t* collaterals_buffer_ptr = NULL;

    /* Test 1: Verify report with collaterals */
    OE_TEST(
        GetReport_v2(
            flags, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size) ==
        OE_OK);

    /* Verify report without collaterals */
    OE_TEST(
        VerifyReportWithCollaterals(
            report_buffer_ptr, report_ptr_size, NULL, 0, NULL, NULL) == OE_OK);

    if (GetCollaterals(&collaterals_buffer_ptr, &collaterals_ptr_size) == OE_OK)
    {
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                NULL, // Validate using current time
                NULL) == OE_OK);

        /* Test with time in the past */
        time_t t;
        struct tm timeinfo;
        time(&t);
        gmtime_r(&t, &timeinfo);

        // convert tm to oe_datetime_t
        oe_datetime_t past = {(uint32_t)timeinfo.tm_year + 1890,
                              (uint32_t)timeinfo.tm_mon + 1,
                              (uint32_t)timeinfo.tm_mday,
                              (uint32_t)timeinfo.tm_hour,
                              (uint32_t)timeinfo.tm_min,
                              (uint32_t)timeinfo.tm_sec};
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &past,
                NULL) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

        /* Test with time in the future */
        oe_datetime_t future = {(uint32_t)timeinfo.tm_year + 1910,
                                (uint32_t)timeinfo.tm_mon + 1,
                                (uint32_t)timeinfo.tm_mday,
                                (uint32_t)timeinfo.tm_hour,
                                (uint32_t)timeinfo.tm_min,
                                (uint32_t)timeinfo.tm_sec};
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &future,
                NULL) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

        /* Get validity range and use it to validate edge cases.*/
        oe_datetime_t valid_from = {0};
        oe_datetime_t valid_until = {0};
        OE_TEST(
            GetQuoteValidityWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &valid_from,
                &valid_until) == OE_OK);
        /* At latest valid from date */
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &valid_from,
                NULL) == OE_OK);
        /* At earliest expiration date */
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &valid_until,
                NULL) == OE_OK);

        valid_from.year -= 1;
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &valid_from,
                NULL) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

        valid_until.year += 1;
        OE_TEST(
            VerifyReportWithCollaterals(
                report_buffer_ptr,
                report_ptr_size,
                collaterals_buffer_ptr,
                collaterals_ptr_size,
                &valid_until,
                NULL) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);
    }

    oe_free_collaterals(collaterals_buffer_ptr);
    oe_free_report(report_buffer_ptr);

    collaterals_buffer_ptr = NULL;
    report_buffer_ptr = NULL;
}

void test_get_signer_id_from_public_key()
{
    static const char pem[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBoDANBgkqhkiG9w0BAQEFAAOCAY0AMIIBiAKCAYEAqhEGbnOzUfNffyL98nRj\n"
        "FOXYb+4d1Q/CluY3GlbDFv9OphD9zwY8TnSUz/cIBMdphAadGlnjIi8SS9Yey1If\n"
        "RcIW1pMnRaAS8J1Kwh9WgBqBZlA/bFB4a45ZC16l+oeG5/u3MeQsKDsNIT1kfHJD\n"
        "Sb18UHlvEPNcrzIDy+TAcAhd7q/aav1lDp28TgT7kUdVb5HitBzBQ67s4/L6Xzlo\n"
        "yAMqSybT56nnTeADcNa/tvom8vqz0lZ5nXAQ7ZAhGKJKCWk+9aT5oxLNBCrUYQ+U\n"
        "tnJ8429uzBYvG/fyaMcAGjkcfnW2irYSpwfFbpN6Ew2252V6O6KYTcFGKBGQaXKe\n"
        "zflTOOQ6yRUr5a4GqwTsVc6TH+NvpIyL1SgY2zzSkwciqTRyHBh7UpfCC3E3ZNJK\n"
        "T4CUPXu5eINL6v2Wmz8CRbc2hoPoD+oIvLoqcgClihZs3XlGp3D6ULEgKBP5ortC\n"
        "gpUbitgtA0zGLrQlJhKHVkGgwxax1U9wLHPNLxzzsGaJAgED\n"
        "-----END PUBLIC KEY-----\n";

    static const array<uint8_t, OE_SIGNER_ID_SIZE> expected_signer_id{
        0x6c, 0x1c, 0x59, 0xc8, 0x9e, 0xd4, 0xdd, 0x98, 0x25, 0x64, 0x94,
        0x94, 0xfc, 0xb2, 0xeb, 0xf9, 0x6a, 0x8a, 0x61, 0x7a, 0x1d, 0x05,
        0x89, 0xfe, 0x01, 0x47, 0xf0, 0xef, 0x1b, 0x3f, 0x78, 0x4d};

    array<uint8_t, OE_SIGNER_ID_SIZE> actual_signer_id{};
    size_t size = actual_signer_id.size();
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), actual_signer_id.data(), &size) == OE_OK);
    OE_TEST(size == OE_SIGNER_ID_SIZE);
    OE_TEST(expected_signer_id == actual_signer_id);

    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            nullptr, sizeof(pem), actual_signer_id.data(), &size) ==
        OE_INVALID_PARAMETER);
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, 0, actual_signer_id.data(), &size) == OE_INVALID_PARAMETER);
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem) - 1, actual_signer_id.data(), &size) ==
        OE_INVALID_PARAMETER);
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), nullptr, nullptr) == OE_INVALID_PARAMETER);
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), actual_signer_id.data(), nullptr) ==
        OE_INVALID_PARAMETER);

    size = 0;
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), actual_signer_id.data(), &size) ==
        OE_BUFFER_TOO_SMALL);
    OE_TEST(size == OE_SIGNER_ID_SIZE);

    size = 0;
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), nullptr, &size) == OE_BUFFER_TOO_SMALL);
    OE_TEST(size == OE_SIGNER_ID_SIZE);

    size = OE_SIGNER_ID_SIZE - 1;
    OE_TEST(
        oe_sgx_get_signer_id_from_public_key(
            pem, sizeof(pem), actual_signer_id.data(), &size) ==
        OE_BUFFER_TOO_SMALL);
    OE_TEST(size == OE_SIGNER_ID_SIZE);
}
