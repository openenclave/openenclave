// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/sgx/eeid_attester.h>
#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/eeid_plugin.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "../test_helpers.h"
#include "eeid_plugin_t.h"

static const oe_uuid_t _eeid_uuid = {OE_FORMAT_UUID_SGX_EEID_ECDSA_P256};

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
    OE_TEST_CODE(oe_sgx_eeid_attester_initialize(), OE_OK);
}

static void _test_and_register_verifier()
{
    printf("====== running _test_and_register_verifier\n");
    OE_TEST_CODE(oe_sgx_eeid_verifier_initialize(), OE_OK);
}

static void _test_and_unregister_attester()
{
    printf("====== running _test_and_unregister_attester\n");
    OE_TEST_CODE(oe_sgx_eeid_attester_shutdown(), OE_OK);
}

static void _test_and_unregister_verifier()
{
    printf("====== running _test_and_unregister_verifier\n");
    OE_TEST_CODE(oe_sgx_eeid_verifier_shutdown(), OE_OK);
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
        claims,
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

    // Verify evidence without endorsements.
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_length) == OE_OK);

    OE_TEST(oe_free_claims(claims, claims_length) == OE_OK);

    // Verify with endorsements.
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

    OE_TEST(
        host_ocall_verify(
            evidence, evidence_size, endorsements, endorsements_size) == OE_OK);

    OE_TEST(oe_free_claims(claims, claims_length) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    OE_TEST(oe_free_evidence(evidence) == OE_OK);
#endif
}

static void _test_get_evidence_fail()
{
    printf("====== running _test_get_evidence_fail\n");

    uint8_t* evidence;
    size_t evidence_size;

    // Test get_evidence when plugin is unregistered.
    OE_TEST_CODE(oe_sgx_eeid_attester_shutdown(), OE_OK);

    OE_TEST_CODE(
        oe_get_evidence(
            &_eeid_uuid,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            NULL),
        OE_NOT_FOUND);

    OE_TEST_CODE(oe_sgx_eeid_attester_initialize(), OE_OK);
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

    OE_TEST_CODE(
        oe_get_evidence(
            &_eeid_uuid,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size),
        OE_OK);

    // Test verify_evidence with wrong sizes
    OE_TEST_CODE(
        oe_verify_evidence(
            evidence,
            0,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_INVALID_PARAMETER);

    OE_TEST_CODE(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            0,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_INVALID_PARAMETER);

    // Test verify evidence when plugin is unregistered
    OE_TEST_CODE(oe_sgx_eeid_verifier_shutdown(), OE_OK);
    OE_TEST_CODE(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_NOT_FOUND);
    OE_TEST_CODE(oe_sgx_eeid_verifier_initialize(), OE_OK);

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
    _test_evidence_success(&_eeid_uuid);

    // Test failures.
    _test_get_evidence_fail();
    _test_verify_evidence_fail();

    // Test unregister functions
    _test_and_unregister_attester();
    _test_and_unregister_verifier();
}

oe_result_t get_eeid_evidence(
    uint8_t* evidence,
    size_t evidence_size,
    size_t* evidence_out_size,
    uint8_t* endorsements,
    size_t endorsements_size,
    size_t* endorsements_out_size)
{
    uint8_t* local_evidence = NULL;
    size_t local_evidence_size = 0;
    uint8_t* local_endorsements = NULL;
    size_t local_endorsements_size = 0;

    OE_TEST_CODE(oe_sgx_eeid_attester_initialize(), OE_OK);

    OE_TEST_CODE(
        oe_get_evidence(
            &_eeid_uuid,
            NULL,
            0,
            NULL,
            0,
            &local_evidence,
            &local_evidence_size,
            &local_endorsements,
            &local_endorsements_size),
        OE_OK);

    if (local_evidence_size > evidence_size ||
        local_endorsements_size > endorsements_size)
        return OE_BUFFER_TOO_SMALL;

    *evidence_out_size = local_evidence_size;
    *endorsements_out_size = local_endorsements_size;

    memcpy(evidence, local_evidence, local_evidence_size);
    memcpy(endorsements, local_endorsements, local_endorsements_size);

    OE_TEST_CODE(oe_sgx_eeid_attester_shutdown(), OE_OK);

    return OE_OK;
}
