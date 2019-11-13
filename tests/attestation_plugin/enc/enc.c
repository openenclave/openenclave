// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/attester.h>
#include <openenclave/attestation/sgx/verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "../plugin/tests.h"
#include "plugin_t.h"

oe_attester_t* sgx_attest = NULL;

void run_runtime_test()
{
    test_runtime();
}

void register_sgx()
{
    printf("====== running register_sgx\n");

    sgx_attest = oe_sgx_plugin_attester();
    OE_TEST(oe_register_attester(sgx_attest, NULL, 0) == OE_OK);
    register_verifier();
}

void unregister_sgx()
{
    printf("====== running unregister_sgx\n");

    OE_TEST(oe_unregister_attester(sgx_attest) == OE_OK);
    sgx_attest = NULL;
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
    OE_TEST(
        oe_get_evidence(
            &sgx_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);

    verify_sgx_evidence(evidence, evidence_size, NULL, 0, NULL, 0);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);

    // Get a remote report with endorsements.
    printf("====== running _test_sgx_remote #2: + Endorsements\n");
    OE_TEST(
        oe_get_evidence(
            &sgx_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);

    verify_sgx_evidence(
        evidence, evidence_size, endorsements, endorsements_size, NULL, 0);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);

    // Get a remote report with both.
    printf("====== running _test_sgx_remote #3: + Claims\n");
    OE_TEST(
        oe_get_evidence(
            &sgx_attest->base.format_id,
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            test_claims,
            NUM_TEST_CLAIMS,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);

    verify_sgx_evidence(
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        test_claims,
        NUM_TEST_CLAIMS);

    OE_TEST(
        host_verify(evidence, evidence_size, endorsements, endorsements_size) ==
        OE_OK);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

void test_sgx()
{
    printf("====== running test_sgx\n");
    _test_sgx_remote();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
