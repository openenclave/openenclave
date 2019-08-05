// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/tests.h"
#include <openenclave/internal/tests.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/corelibc/string.h>

#define GetReport oe_get_report
#define GetReport_v2 oe_get_report_v2

#define VerifyReport oe_verify_report

#else

// The host side API requires the enclave to be passed in.

oe_enclave_t* g_enclave = NULL;

// Host side API does not have report_data and report_data_size
#define GetReport(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report(g_enclave, flags, op, ops, rb, rbs)
#define GetReport_v2(flags, rd, rds, op, ops, rb, rbs) \
    oe_get_report_v2(g_enclave, flags, op, ops, rb, rbs)

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
        OE_TEST(
            GetReport_v2(
                0,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                NULL,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
    }

    {
        OE_TEST(
            GetReport_v2(
                0,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                opt_params,
                5,
                &report_buffer_ptr,
                &report_ptr_size) == OE_INVALID_PARAMETER);

        OE_TEST(
            GetReport_v2(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size) ==
            OE_OK);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;
        OE_TEST(
            GetReport(
                0, NULL, 0, NULL, 0, &report_buffer_ptr, &report_ptr_size) ==
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
        OE_TEST(
            GetReport_v2(
                0,
                NULL,
                0,
                opt_params,
                sizeof(sgx_target_info_t),
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);
        report_buffer_ptr = NULL;

        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                opt_params,
                sizeof(sgx_target_info_t),
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
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
        OE_TEST(
            GetReport_v2(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
        OE_TEST(report_ptr_size == OE_LOCAL_REPORT_SIZE);
        ValidateReport(
            report_buffer_ptr,
            report_ptr_size,
            false,
            zeros,
            OE_REPORT_DATA_SIZE);
        oe_free_report(report_buffer_ptr);

        OE_TEST(
            GetReport(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);
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

        OE_TEST(
            GetReport_v2(
                0,
                NULL,
                0,
                target_info,
                sizeof(opt_params),
                &report_buffer_ptr,
                &report_ptr_size) == OE_OK);

        OE_TEST(
            oe_get_target_info_v2(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                &target_ptr_size) == OE_OK);
        OE_TEST(target_ptr_size == sizeof(target));
        oe_free_target_info(target_ptr);

        target_ptr = NULL;
        target_ptr_size = 0;
        OE_TEST(
            oe_get_target_info(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                &target_ptr_size) == OE_OK);
        OE_TEST(target_ptr_size == sizeof(target));
        oe_free_target_info(target_ptr);

        /* Failure cases. */
        OE_TEST(
            oe_get_target_info_v2(
                NULL, report_ptr_size, (void**)&target_ptr, &target_ptr_size) ==
            OE_INVALID_PARAMETER);
        OE_TEST(
            oe_get_target_info(
                NULL, report_ptr_size, (void**)&target_ptr, &target_ptr_size) ==
            OE_INVALID_PARAMETER);

        OE_TEST(
            oe_get_target_info_v2(
                report_buffer_ptr,
                sizeof(oe_report_header_t) + sizeof(sgx_report_t) - 1,
                (void**)&target_ptr,
                &target_ptr_size) == OE_INVALID_PARAMETER);
        OE_TEST(
            oe_get_target_info(
                report_buffer_ptr,
                sizeof(oe_report_header_t) + sizeof(sgx_report_t) - 1,
                (void**)&target_ptr,
                &target_ptr_size) == OE_INVALID_PARAMETER);

        OE_TEST(
            oe_get_target_info_v2(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                NULL) == OE_INVALID_PARAMETER);
        OE_TEST(
            oe_get_target_info_v2(
                report_buffer_ptr,
                report_ptr_size,
                (void**)&target_ptr,
                NULL) == OE_INVALID_PARAMETER);

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
    OE_TEST(
        GetReport_v2(
            0,
            NULL,
            0,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size) == OE_OK);
    OE_TEST(VerifyReport(report_ptr, report_size, NULL) == OE_OK);
    oe_free_report(report_ptr);

// 2. Report with full custom report data.
#ifdef OE_BUILD_ENCLAVE
    OE_TEST(
        GetReport_v2(
            0,
            report_data,
            sizeof(report_data),
            target_info,
            target_info_size,
            &report_ptr,
            &report_size) == OE_OK);
    OE_TEST(VerifyReport(report_ptr, report_size, NULL) == OE_OK);
    oe_free_report(report_ptr);

    // 3. Report with partial custom report data.
    OE_TEST(
        GetReport_v2(
            0,
            report_data,
            sizeof(report_data) / 2,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size) == OE_OK);
    OE_TEST(VerifyReport(report_ptr, report_size, NULL) == OE_OK);
    oe_free_report(report_ptr);
#endif

    // 4. Negative case.

    // Tamper with the target info.
    tampered_target_info = (sgx_target_info_t*)target_info;
    tampered_target_info->mrenclave[0]++;

    OE_TEST(
        GetReport_v2(
            0,
            NULL,
            0,
            target_info,
            target_info_size,
            &report_ptr,
            &report_size) == OE_OK);
    OE_TEST(
        VerifyReport(report_ptr, report_size, NULL) ==
        OE_VERIFY_FAILED_OES_CMAC_MISMATCH);
    oe_free_report(report_ptr);
}

void test_remote_verify_report()
{
    uint8_t* report_ptr;
    size_t report_size;

#if OE_BUILD_ENCLAVE
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
        OE_TEST(
            GetReport_v2(flags, NULL, 0, NULL, 0, &report_ptr, &report_size) ==
            OE_OK);
        OE_TEST(VerifyReport(report_ptr, report_size, NULL) == OE_OK);
        oe_free_report(report_ptr);

#if OE_BUILD_ENCLAVE
        report_data_size = 16;
        OE_TEST(
            GetReport_v2(
                flags,
                report_data,
                report_data_size,
                NULL,
                0,
                &report_ptr,
                &report_size) == OE_OK);
        OE_TEST(VerifyReport(report_ptr, report_size, NULL) == OE_OK);
        oe_free_report(report_ptr);
#endif
    }
}
