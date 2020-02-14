// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/plugin.h>
#include <openenclave/attestation/sgx/verifier.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/sgx/quote.h"
#include "mock_attester.h"
#include "tests.h"

oe_verifier_t* sgx_verify = NULL;

typedef struct _header
{
    uint32_t version;
    oe_uuid_t format_id;
    uint64_t data_size;
    uint8_t data[];
} header_t;

oe_claim_t test_claims[2] = {{.name = CLAIM1_NAME,
                              .value = (uint8_t*)CLAIM1_VALUE,
                              .value_size = sizeof(CLAIM1_VALUE)},
                             {.name = CLAIM2_NAME,
                              .value = (uint8_t*)CLAIM2_VALUE,
                              .value_size = sizeof(CLAIM2_VALUE)}};

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
    printf("====== running _test_and_register_attester\n");
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
    printf("====== running _test_and_register_verifier\n");
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
    printf("====== running _test_and_unregister_attester\n");
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_OK);
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester(&mock_attester2) == OE_OK);
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester(&mock_attester2) == OE_NOT_FOUND);
}

static void _test_and_unregister_verifier()
{
    printf("====== running _test_and_unregister_verifier\n");
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_OK);
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier(&mock_verifier2) == OE_OK);
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier(&mock_verifier2) == OE_NOT_FOUND);
}

static bool _find_format_id(
    const oe_uuid_t* target_format_id,
    const oe_uuid_t* format_ids,
    size_t format_ids_length)
{
    for (size_t n = 0; n < format_ids_length; n++)
    {
        if (memcmp(
                (void*)&format_ids[n], target_format_id, sizeof(oe_uuid_t)) ==
            0)
        {
            return true;
        }
    }
    return false;
}

static void _test_attester_format_id_query()
{
    printf("====== running _test_attester_format_id_query\n");
    const oe_uuid_t mock_attester_uuid1 = {0x01,
                                           0x2f,
                                           0x70,
                                           0x55,
                                           0x4d,
                                           0xa2,
                                           0x4e,
                                           0xb4,
                                           0xb7,
                                           0x68,
                                           0x44,
                                           0x95,
                                           0x25,
                                           0x44,
                                           0x02,
                                           0x0a};
    const oe_uuid_t mock_attester_uuid2 = {0x02,
                                           0x2f,
                                           0x70,
                                           0x55,
                                           0x4d,
                                           0xa2,
                                           0x4e,
                                           0xb4,
                                           0xb7,
                                           0x68,
                                           0x44,
                                           0x95,
                                           0x25,
                                           0x44,
                                           0x02,
                                           0x0a};

    oe_attester_t mock_attester1 = {.base = {.format_id = mock_attester_uuid1}};
    oe_attester_t mock_attester2 = {.base = {.format_id = mock_attester_uuid2}};

    oe_uuid_t* format_ids = NULL;
    size_t format_ids_length0 = 99;
    size_t format_ids_length1 = 99;
    size_t format_ids_length2 = 99;

    // Both registered attesters should be found.
    OE_TEST(
        oe_get_registered_attester_format_ids(NULL, &format_ids_length0) ==
        OE_OK);
    OE_TEST(oe_register_attester(&mock_attester1, NULL, 0) == OE_OK);
    OE_TEST(oe_register_attester(&mock_attester2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_get_registered_attester_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == (format_ids_length0 + 2));
    OE_TEST(
        _find_format_id(&mock_attester_uuid1, format_ids, format_ids_length1));
    OE_TEST(
        _find_format_id(&mock_attester_uuid2, format_ids, format_ids_length1));
    OE_TEST(oe_free_format_ids(format_ids) == OE_OK);

    // Dup attester should not be added to the list.
    OE_TEST(
        oe_register_attester(&mock_attester1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(
        oe_get_registered_attester_format_ids(NULL, &format_ids_length2) ==
        OE_OK);
    OE_TEST(format_ids_length2 == format_ids_length1);

    // Unregistered attester should be removed.
    OE_TEST(oe_unregister_attester(&mock_attester1) == OE_OK);
    OE_TEST(
        oe_get_registered_attester_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == format_ids_length0 + 1);
    OE_TEST(
        !_find_format_id(&mock_attester_uuid1, format_ids, format_ids_length1));
    OE_TEST(
        _find_format_id(&mock_attester_uuid2, format_ids, format_ids_length1));

    OE_TEST(oe_unregister_attester(&mock_attester2) == OE_OK);
    OE_TEST(
        oe_get_registered_attester_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == format_ids_length0);
    OE_TEST(
        !_find_format_id(&mock_attester_uuid2, format_ids, format_ids_length1));

    OE_TEST(oe_free_format_ids(format_ids) == OE_OK);
}

static void _test_verifier_format_id_query()
{
    printf("====== running _test_verifier_format_id_query\n");
    const oe_uuid_t mock_verifier_uuid1 = {0x11,
                                           0x2f,
                                           0x70,
                                           0x55,
                                           0x4d,
                                           0xa2,
                                           0x4e,
                                           0xb4,
                                           0xb7,
                                           0x68,
                                           0x44,
                                           0x95,
                                           0x25,
                                           0x44,
                                           0x02,
                                           0x0a};
    const oe_uuid_t mock_verifier_uuid2 = {0x12,
                                           0x2f,
                                           0x70,
                                           0x55,
                                           0x4d,
                                           0xa2,
                                           0x4e,
                                           0xb4,
                                           0xb7,
                                           0x68,
                                           0x44,
                                           0x95,
                                           0x25,
                                           0x44,
                                           0x02,
                                           0x0a};

    oe_verifier_t mock_verifier1 = {.base = {.format_id = mock_verifier_uuid1}};
    oe_verifier_t mock_verifier2 = {.base = {.format_id = mock_verifier_uuid2}};

    oe_uuid_t* format_ids = NULL;
    size_t format_ids_length0 = 99;
    size_t format_ids_length1 = 99;
    size_t format_ids_length2 = 99;

    // Both registered verifiers should be found.
    OE_TEST(
        oe_get_registered_verifier_format_ids(NULL, &format_ids_length0) ==
        OE_OK);
    OE_TEST(oe_register_verifier(&mock_verifier1, NULL, 0) == OE_OK);
    OE_TEST(oe_register_verifier(&mock_verifier2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_get_registered_verifier_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == (format_ids_length0 + 2));
    OE_TEST(
        _find_format_id(&mock_verifier_uuid1, format_ids, format_ids_length1));
    OE_TEST(
        _find_format_id(&mock_verifier_uuid2, format_ids, format_ids_length1));
    OE_TEST(oe_free_format_ids(format_ids) == OE_OK);

    // Dup verifier should not be added to the list.
    OE_TEST(
        oe_register_verifier(&mock_verifier1, NULL, 0) == OE_ALREADY_EXISTS);
    OE_TEST(
        oe_get_registered_verifier_format_ids(NULL, &format_ids_length2) ==
        OE_OK);
    OE_TEST(format_ids_length2 == format_ids_length1);

    // Unregistered verifier should be removed.
    OE_TEST(oe_unregister_verifier(&mock_verifier1) == OE_OK);
    OE_TEST(
        oe_get_registered_verifier_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == format_ids_length0 + 1);
    OE_TEST(
        !_find_format_id(&mock_verifier_uuid1, format_ids, format_ids_length1));
    OE_TEST(
        _find_format_id(&mock_verifier_uuid2, format_ids, format_ids_length1));

    OE_TEST(oe_unregister_verifier(&mock_verifier2) == OE_OK);
    OE_TEST(
        oe_get_registered_verifier_format_ids(
            &format_ids, &format_ids_length1) == OE_OK);
    OE_TEST(format_ids_length1 == format_ids_length0);
    OE_TEST(
        !_find_format_id(&mock_verifier_uuid2, format_ids, format_ids_length1));

    OE_TEST(oe_free_format_ids(format_ids) == OE_OK);
}

static void _test_evidence_success(
    const oe_uuid_t* format_id,
    bool use_endorsements)
{
    printf("====== running _test_evidence_success\n");

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
    printf("====== running _test_get_evidence_fail\n");

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
    printf("====== running _test_verify_evidence_fail\n");

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

void test_runtime()
{
    printf("====== running test_runtime\n");

    // Test format id query functions.
    _test_attester_format_id_query();
    _test_verifier_format_id_query();

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

void register_verifier()
{
    sgx_verify = oe_sgx_plugin_verifier();
    OE_TEST(oe_register_verifier(sgx_verify, NULL, 0) == OE_OK);
}

void unregister_verifier()
{
    OE_TEST(oe_unregister_verifier(sgx_verify) == OE_OK);
    sgx_verify = NULL;
}

static void* _find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return claims[i].value;
    }
    return NULL;
}

static void _test_time(
    const uint8_t* report,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    oe_datetime_t tmp;
    oe_report_header_t* header = (oe_report_header_t*)report;

    OE_TEST(
        oe_verify_sgx_quote(
            header->report,
            header->report_size,
            collaterals,
            collaterals_size,
            from) == OE_OK);

    OE_TEST(
        oe_verify_sgx_quote(
            header->report,
            header->report_size,
            collaterals,
            collaterals_size,
            until) == OE_OK);

    tmp = *from;
    tmp.year--;
    OE_TEST(
        oe_verify_sgx_quote(
            header->report,
            header->report_size,
            collaterals,
            collaterals_size,
            &tmp) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

    tmp = *until;
    tmp.year++;
    OE_TEST(
        oe_verify_sgx_quote(
            header->report,
            header->report_size,
            collaterals,
            collaterals_size,
            &tmp) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);
}

static void _test_time_policy(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    oe_policy_t policy;
    oe_datetime_t dt;
    oe_claim_t* claims;
    size_t claims_size;

    policy.type = OE_POLICY_ENDORSEMENTS_TIME;
    policy.policy = (void*)&dt;
    policy.policy_size = sizeof(dt);

    dt = *from;
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size) == OE_OK);
    OE_TEST(oe_free_claims_list(claims, claims_size) == OE_OK);

    dt = *until;
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size) == OE_OK);
    OE_TEST(oe_free_claims_list(claims, claims_size) == OE_OK);

    dt = *from;
    dt.year--;
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

    dt = *until;
    dt.year++;
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size) == OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);
}

void verify_sgx_evidence(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    const oe_claim_t* custom_claims,
    size_t custom_claims_size,
    bool is_local)
{
    printf("====== running verify_sgx_evidence\n");

    header_t* header = (header_t*)evidence;
    header_t* header_endorsements = (header_t*)endorsements;
    oe_report_t report;
    oe_claim_t* claims = NULL;
    size_t claims_size = 0;
    size_t extra_size = 0;
    void* value;
    void* from;
    void* until;

    // Try with no policies.
    OE_TEST(
        oe_verify_evidence(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_size) == OE_OK);

    // Make sure that the identity info matches with the regular oe report.
    // We need to remove the attestation header and the claims first.
    extra_size = sizeof(oe_sgx_plugin_claims_header_t);
    for (size_t i = 0; i < custom_claims_size; i++)
    {
        extra_size += sizeof(oe_sgx_plugin_claims_entry_t);
        extra_size += strlen(custom_claims[i].name) + 1;
        extra_size += custom_claims[i].value_size;
    }

    OE_TEST(
        oe_parse_report(
            header->data, header->data_size - extra_size, &report) == OE_OK);

    // Check id version.
    value = _find_claim(claims, claims_size, OE_CLAIM_ID_VERSION);
    OE_TEST(value != NULL && *((uint32_t*)value) == report.identity.id_version);

    // Check security version.
    value = _find_claim(claims, claims_size, OE_CLAIM_SECURITY_VERSION);
    OE_TEST(
        value != NULL &&
        *((uint32_t*)value) == report.identity.security_version);

    // Check attributes
    value = _find_claim(claims, claims_size, OE_CLAIM_ATTRIBUTES);
    OE_TEST(value != NULL && *((uint64_t*)value) == report.identity.attributes);

    // Check unique ID
    value = _find_claim(claims, claims_size, OE_CLAIM_UNIQUE_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             &report.identity.unique_id,
                             sizeof(report.identity.unique_id)) == 0);

    // Check signer ID
    value = _find_claim(claims, claims_size, OE_CLAIM_SIGNER_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             &report.identity.signer_id,
                             sizeof(report.identity.signer_id)) == 0);

    // Check product ID
    value = _find_claim(claims, claims_size, OE_CLAIM_PRODUCT_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             &report.identity.product_id,
                             sizeof(report.identity.product_id)) == 0);

    // Check UUID.
    value = _find_claim(claims, claims_size, OE_CLAIM_PLUGIN_UUID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             &sgx_verify->base.format_id,
                             sizeof(sgx_verify->base.format_id)) == 0);

    // Check date time.
    from = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_FROM);
    OE_TEST(is_local || from != NULL);

    until = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_UNTIL);
    OE_TEST(is_local || until != NULL);

    if (!is_local && endorsements)
    {
        _test_time(
            header->data,
            endorsements ? header_endorsements->data : NULL,
            endorsements ? header_endorsements->data_size : 0,
            (oe_datetime_t*)from,
            (oe_datetime_t*)until);

        _test_time_policy(
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            (oe_datetime_t*)from,
            (oe_datetime_t*)until);
    }

    // Check custom claims.
    if (custom_claims)
    {
        for (size_t i = 0; i < custom_claims_size; i++)
        {
            value = _find_claim(claims, claims_size, custom_claims[i].name);
            OE_TEST(
                value != NULL && memcmp(
                                     custom_claims[i].value,
                                     value,
                                     custom_claims[i].value_size) == 0);
        }
    }

    OE_TEST(oe_free_claims_list(claims, claims_size) == OE_OK);
}