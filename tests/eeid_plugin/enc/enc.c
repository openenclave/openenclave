// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/eeid_attester.h>
#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "../test_helpers.h"
#include "eeid_plugin_t.h"

typedef struct _header
{
    uint32_t version;
    oe_uuid_t format_id;
    uint64_t data_size;
    uint8_t data[];
} header_t;

static void _test_and_register_attester()
{
    printf("====== running _test_and_register_attester\n");
    OE_TEST(oe_register_attester(&eeid_attester, NULL, 0) == OE_OK);
    OE_TEST(oe_register_attester(&eeid_attester, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(oe_register_attester(&eeid_attester, NULL, 0) == OE_ALREADY_EXISTS);
}

static void _test_and_register_verifier()
{
    printf("====== running _test_and_register_verifier\n");
    OE_TEST(oe_register_verifier(&eeid_verifier, NULL, 0) == OE_OK);
    OE_TEST(oe_register_verifier(&eeid_verifier, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(oe_register_verifier(&eeid_verifier, NULL, 0) == OE_ALREADY_EXISTS);
}

static void _test_and_unregister_attester()
{
    printf("====== running _test_and_unregister_attester\n");
    OE_TEST(oe_unregister_attester(&eeid_attester) == OE_OK);
    OE_TEST(oe_unregister_attester(&eeid_attester) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester(&eeid_attester) == OE_NOT_FOUND);
}

static void _test_and_unregister_verifier()
{
    printf("====== running _test_and_unregister_verifier\n");
    OE_TEST(oe_unregister_verifier(&eeid_verifier) == OE_OK);
    OE_TEST(oe_unregister_verifier(&eeid_verifier) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier(&eeid_verifier) == OE_NOT_FOUND);
}

static header_t* make_endorsements(
    const oe_eeid_t* eeid,
    size_t* endorsements_size)
{
    oe_uuid_t plugin_uuid = OE_EEID_PLUGIN_UUID;
    size_t eeid_size = sizeof(oe_eeid_t) + eeid->data_size;
    *endorsements_size = sizeof(header_t) + eeid_size;
    header_t* endorsements = malloc(*endorsements_size);
    endorsements->version = 1;
    endorsements->format_id = plugin_uuid;
    endorsements->data_size = eeid_size;
    memcpy(endorsements->data, eeid, eeid_size);
    return endorsements;
}

static void _test_evidence_success(const oe_uuid_t* format_id)
{
    printf("====== running _test_evidence_success\n");

    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    oe_result_t r = oe_get_evidence(
        format_id,
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        claims_length,
        NULL,
        0,
        &evidence,
        &evidence_size,
        &endorsements,
        &endorsements_size);

#ifndef _OE_ENCLAVE_H
    OE_UNUSED(_check_claims);
    OE_TEST(r == OE_UNSUPPORTED);
#else
    OE_TEST(r == OE_OK);

    oe_eeid_t* eeid = mk_test_eeid();
    size_t v_endorsements_size = 0;
    header_t* v_endorsements = make_endorsements(eeid, &v_endorsements_size);

    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            (uint8_t*)v_endorsements,
            v_endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_OK);

    free(v_endorsements);
    free(eeid);
    free(endorsements);
#endif

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_claims_list(claims, claims_length) == OE_OK);
}

static void _test_get_evidence_fail()
{
    printf("====== running _test_get_evidence_fail\n");

    uint8_t* evidence;
    size_t evidence_size;

    // Test get_evidence when plugin is unregistered.
    OE_TEST(oe_unregister_attester(&eeid_attester) == OE_OK);

    OE_TEST(
        oe_get_evidence(
            &eeid_attester.base.format_id,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            NULL) == OE_NOT_FOUND);

    OE_TEST(oe_register_attester(&eeid_attester, NULL, 0) == OE_OK);
}

static void _test_verify_evidence_fail()
{
    printf("====== running _test_verify_evidence_fail\n");

    uint8_t* evidence;
    size_t evidence_size;
    uint8_t* endorsements;
    size_t endorsements_size;
    oe_claim_t* claims;
    size_t claims_length;

    OE_TEST(
        oe_get_evidence(
            &eeid_attester.base.format_id,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);

    // Test verify_evidence with wrong sizes
    OE_TEST(
        oe_verify_evidence(
            evidence,
            0,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_INVALID_PARAMETER);

    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            0,
            NULL,
            0,
            &claims,
            &claims_length) == OE_INVALID_PARAMETER);

    // Test verify evidence when plugin is unregistered
    OE_TEST(oe_unregister_verifier(&eeid_verifier) == OE_OK);
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_NOT_FOUND);
    OE_TEST(oe_register_verifier(&eeid_verifier, NULL, 0) == OE_OK);

    // Test verify when evidence / endorsement id don't match?
    // Test faulty verifier when they don't have the right claims?

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

void run_tests()
{
    printf("====== running run_tests\n");

    // Test register functions.
    _test_and_register_attester();
    _test_and_register_verifier();

    // Test get evidence + verify evidence with the proper claims.
    _test_evidence_success(&eeid_attester.base.format_id);

    // Test failures.
    _test_get_evidence_fail();
    _test_verify_evidence_fail();

    // Test unregister functions
    _test_and_unregister_attester();
    _test_and_unregister_verifier();
}