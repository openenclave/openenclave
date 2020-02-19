// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/attestation/sgx/verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "../plugin/tests.h"
#include "plugin_t.h"

oe_attester_t* sgx_local_attest = NULL;
oe_attester_t* sgx_remote_attest = NULL;

void run_runtime_test()
{
    test_runtime();
}

void register_sgx()
{
    printf("====== running register_sgx\n");

    sgx_local_attest = oe_sgx_plugin_local_attester();
#if (OE_API_VERSION < 3)
    sgx_remote_attest = oe_sgx_plugin_attester();
#else
    sgx_remote_attest = oe_sgx_plugin_ecdsa_p256_attester();
#endif
    OE_TEST(oe_register_attester(sgx_local_attest, NULL, 0) == OE_OK);
    OE_TEST(oe_register_attester(sgx_remote_attest, NULL, 0) == OE_OK);
    register_verifier();
}

void unregister_sgx()
{
    printf("====== running unregister_sgx\n");

    OE_TEST(oe_unregister_attester(sgx_local_attest) == OE_OK);
    OE_TEST(oe_unregister_attester(sgx_remote_attest) == OE_OK);
    sgx_local_attest = NULL;
    sgx_remote_attest = NULL;
    unregister_verifier();
}

static void _test_sgx_remote()
{
    printf("====== running _test_sgx_remote\n");
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;

    // Get a remote attestation report.
    printf("====== running _test_sgx_remote #1: Just evidence\n");
#if (OE_API_VERSION < 3)
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#else
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#endif

    verify_sgx_evidence(evidence, evidence_size, NULL, 0, NULL, 0, false);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);

    // Get a remote report with endorsements.
    printf("====== running _test_sgx_remote #2: + Endorsements\n");
#if (OE_API_VERSION < 3)
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);
#else
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);
#endif

    verify_sgx_evidence(
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        false);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);

    // Get a remote report with both.
    printf("====== running _test_sgx_remote #3: + Claims\n");
#if (OE_API_VERSION < 3)
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            test_claims,
            NUM_TEST_CLAIMS,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);
#else
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            test_claims,
            NUM_TEST_CLAIMS,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);
#endif

    verify_sgx_evidence(
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        test_claims,
        NUM_TEST_CLAIMS,
        false);

    OE_TEST(
        host_verify(evidence, evidence_size, endorsements, endorsements_size) ==
        OE_OK);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

static void _test_sgx_local()
{
    uint8_t* report = NULL;
    size_t report_size = 0;
    void* target = NULL;
    size_t target_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;

    printf("====== running _test_sgx_local\n");
    printf("====== running _test_sgx_local #0: Getting target info.\n");
    OE_TEST(oe_get_report(0, NULL, 0, NULL, 0, &report, &report_size) == OE_OK);

    OE_TEST(
        oe_get_target_info(report, report_size, &target, &target_size) ==
        OE_OK);

    oe_free_report(report);

    // Only evidence.
    printf("====== running _test_sgx_local #1: Just evidence\n");
#if (OE_API_VERSION < 3)
    OE_TEST(
        oe_get_evidence(
            &sgx_local_attest->base.format_id,
            0,
            NULL,
            0,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#else
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            NULL,
            0,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#endif

    verify_sgx_evidence(evidence, evidence_size, NULL, 0, NULL, 0, true);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);

    // Evidence + claims.
    printf("====== running _test_sgx_local #2: + Claims\n");
#if (OE_API_VERSION < 3)
    OE_TEST(
        oe_get_evidence(
            &sgx_local_attest->base.format_id,
            0,
            test_claims,
            NUM_TEST_CLAIMS,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#else
    OE_TEST(
        oe_get_evidence(
            &sgx_remote_attest->base.format_id,
            test_claims,
            NUM_TEST_CLAIMS,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);
#endif

    verify_sgx_evidence(
        evidence, evidence_size, NULL, 0, test_claims, NUM_TEST_CLAIMS, true);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    oe_free_target_info(target);
}

void test_sgx()
{
    printf("====== running test_sgx\n");

    _test_sgx_remote();
    _test_sgx_local();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
