// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include "../../../common/quote.h"
#include "../../../common/tcbinfo.h"
#include "../common/tests.cpp"
#include "tests_t.h"

oe_result_t test_verify_tcb_info(
    const char* tcb_info,
    oe_tcb_level_t* platform_tcb_level,
    oe_parsed_tcb_info_t* parsed_tcb_info)
{
#ifdef OE_USE_LIBSGX
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
#ifdef OE_USE_LIBSGX
    static uint8_t report[OE_MAX_REPORT_SIZE];
    size_t report_size = sizeof(report);

    // Generate reports.
    OE_TEST(
        oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            report,
            &report_size) == OE_OK);

    // Verify the report.
    OE_TEST(oe_verify_report(report, report_size, NULL) == OE_OK);

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

    printf("test_minimum_issue_date passed.\n");
#else
    OE_UNUSED(now);
#endif
}

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
