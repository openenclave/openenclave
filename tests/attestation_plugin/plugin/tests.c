// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/plugin.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mock_attester.h"
#include "tests.h"

static bool _check_claims(const oe_claim_t* claims, size_t claims_length)
{
    for (size_t i = 0; i < OE_REQUIRED_CLAIMS_COUNT; i++)
    {
        bool found = false;

        for (size_t j = 0; j < claims_length && !found; j++)
        {
            if (strcmp(OE_REQUIRED_CLAIMS[i], claims[j].name) == 0)
            {
                found = true;
            }
        }

        if (!found)
            return false;
    }
    return true;
}

static void _test_and_register_attester()
{
    OE_TEST(oe_register_attester(&mock_attester1, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_attester(&mock_attester1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(oe_register_attester(&mock_attester2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_attester(&mock_attester1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(
        oe_register_attester(&mock_attester2, NULL, 0) == OE_ALREADY_EXISTS);
}

static void _test_and_register_verifier()
{
    OE_TEST(oe_register_verifier(&mock_verifier1, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_verifier(&mock_verifier1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(oe_register_verifier(&mock_verifier2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_verifier(&mock_verifier1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(
        oe_register_verifier(&mock_verifier2, NULL, 0) == OE_ALREADY_EXISTS);
}

static void _test_and_unregister_attester()
{
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_OK);
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester(&mock_attester2) == OE_OK);
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester(&mock_attester2) == OE_NOT_FOUND);
}

static void _test_and_unregister_verifier()
{
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_OK);
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier(&mock_verifier2) == OE_OK);
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier(&mock_verifier2) == OE_NOT_FOUND);
}

static void _test_evidence_success(
    const uuid_t* format_id,
    bool use_endorsements)
{
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_TEST(
        oe_get_evidence(
            format_id,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            use_endorsements ? &endorsements : NULL,
            use_endorsements ? &endorsements_size : NULL) == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_OK);

    OE_TEST(_check_claims(claims, claims_length));

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    OE_TEST(oe_free_claims_list(claims, claims_length) == OE_OK);
}

static void _test_get_evidence_fail()
{
    uint8_t* evidence;
    size_t evidence_size;

    // Test get_evidence when plugin is unregistered.
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_OK);

    OE_TEST(
        oe_get_evidence(
            &mock_attester1.base.format_id,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            NULL) == OE_NOT_FOUND);

    OE_TEST(oe_register_attester(&mock_attester1, NULL, 0) == OE_OK);
}

static void _test_verify_evidence_fail()
{
    uint8_t* evidence;
    size_t evidence_size;
    uint8_t* endorsements;
    size_t endorsements_size;
    oe_claim_t* claims;
    size_t claims_length;

    OE_TEST(
        oe_get_evidence(
            &mock_attester1.base.format_id,
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
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_OK);
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
    OE_TEST(oe_register_verifier(&mock_verifier1, NULL, 0) == OE_OK);

    // Test verify when evidence / endorsement id don't match
    uint8_t* evidence2;
    size_t evidence2_size;
    uint8_t* endorsements2;
    size_t endorsements2_size;
    oe_claim_t* claims2;
    size_t claims2_length;

    OE_TEST(
        oe_get_evidence(
            &mock_attester2.base.format_id,
            0,
            NULL,
            0,
            NULL,
            0,
            &evidence2,
            &evidence2_size,
            &endorsements2,
            &endorsements2_size) == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            evidence2,
            evidence2_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims2,
            &claims2_length) == OE_CONSTRAINT_FAILED);

    OE_TEST(oe_free_evidence(evidence2) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements2) == OE_OK);

    // Test faulty verifier when they don't have the right claims.
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_OK);
    OE_TEST(oe_register_verifier(&bad_verifier, NULL, 0) == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_CONSTRAINT_FAILED);

    OE_TEST(oe_unregister_verifier(&bad_verifier) == OE_OK);
    OE_TEST(oe_register_verifier(&mock_verifier1, NULL, 0) == OE_OK);
    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

void test_run_all()
{
    // Test register functions.
    _test_and_register_attester();
    _test_and_register_verifier();

    // Test get evidence + verify evidence with the proper claims.
    // Should work with and without endorsements.
    _test_evidence_success(&mock_attester1.base.format_id, true);
    _test_evidence_success(&mock_attester2.base.format_id, true);
    _test_evidence_success(&mock_attester1.base.format_id, false);
    _test_evidence_success(&mock_attester2.base.format_id, false);

    // Test failures.
    _test_get_evidence_fail();
    _test_verify_evidence_fail();

    // Test unregister functions
    _test_and_unregister_attester();
    _test_and_unregister_verifier();
}