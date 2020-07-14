// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/sgx/quote.h"
#include "../../../common/sgx/tcbinfo.h"
#include "../common/tests.h"
#include "tests_t.h"

oe_result_t test_verify_tcb_info(
    const char* tcb_info,
    oe_tcb_info_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_tcb_info)
{
#ifdef OE_HAS_SGX_DCAP_QL
    return oe_parse_tcb_info_json(
        (const uint8_t*)tcb_info,
        strlen(tcb_info) + 1,
        platform_tcb_level,
        parsed_tcb_info);
#else
    OE_UNUSED(tcb_info);
    OE_UNUSED(platform_tcb_level);
    OE_UNUSED(parsed_tcb_info);
    return OE_OK;
#endif
}

void test_minimum_issue_date(oe_datetime_t now)
{
#ifdef OE_HAS_SGX_DCAP_QL
    static uint8_t* report;
    size_t report_size = 0;
    static uint8_t* report_v2;
    size_t report_v2_size = 0;

    // Generate reports.
    OE_TEST(
        oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &report,
            &report_size) == OE_OK);

    // Verify the report.
    OE_TEST(oe_verify_report(report, report_size, NULL) == OE_OK);

    // Generate reports.
    OE_TEST(
        oe_get_report_v2(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &report_v2,
            &report_v2_size) == OE_OK);

    // Verify the report.
    OE_TEST(oe_verify_report(report_v2, report_v2_size, NULL) == OE_OK);

    // Set the minimum issue date to current time.
    char str[256];
    size_t length = sizeof(str);
    oe_datetime_to_string(&now, str, &length);
    printf("Setting minimum issue date to : %s\n", str);

    // This should cause verification failure since
    // all revocation data (certs, tcbs etc) we generated
    // prior to current time.
    OE_TEST(
        __oe_sgx_set_minimum_crl_tcb_issue_date(
            now.year,
            now.month,
            now.day,
            now.hours,
            now.minutes,
            now.seconds) == OE_OK);

    // Verify the report.
    OE_TEST(
        oe_verify_report(report, report_size, NULL) ==
        OE_INVALID_REVOCATION_INFO);

    OE_TEST(
        oe_verify_report(report_v2, report_v2_size, NULL) ==
        OE_INVALID_REVOCATION_INFO);

    // Restore default minimum CRL/TCB issue date
    OE_TEST(
        __oe_sgx_set_minimum_crl_tcb_issue_date(2017, 3, 17, 0, 0, 0) == OE_OK);

    oe_free_report(report);
    oe_free_report(report_v2);

    printf("test_minimum_issue_date passed.\n");
#else
    OE_UNUSED(now);
#endif
}

void enclave_test_local_report(sgx_target_info_t* target_info)
{
    test_local_report(target_info);
}

void enclave_test_remote_report()
{
    test_remote_report();
}

void enclave_test_parse_report_negative()
{
    test_parse_report_negative();
}

void enclave_test_local_verify_report()
{
    test_local_verify_report();
}

void enclave_test_remote_verify_report()
{
    test_remote_verify_report();
}

void enclave_test_verify_report_with_collaterals()
{
    test_verify_report_with_collaterals();
}

void enclave_test_get_signer_id_from_public_key()
{
    test_get_signer_id_from_public_key();
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
