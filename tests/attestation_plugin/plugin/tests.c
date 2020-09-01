// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/attestation/attester.h>
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../common/attest_plugin.h"
#include "../../../common/sgx/endorsements.h"
#include "../../../common/sgx/quote.h"
#include "../../../common/sgx/report.h"
#include "mock_attester.h"
#include "tests.h"

uint8_t test_claims[TEST_CLAIMS_SIZE] = "This is a sample test claims buffer";
// Should succeed for oe_evidence oe_but fail for oe_report and raw sgx quote.
// As for later two evidence formats, custom claims are placed in report data
// directly which are limited to 64 bytes.
uint8_t test_large_claims[TEST_LARGE_CLAIMS_SIZE] =
    "This is a sample test large claims buffer";

#ifdef OE_BUILD_ENCLAVE
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
    OE_TEST(oe_register_attester_plugin(&mock_attester1, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_attester_plugin(&mock_attester1, NULL, 0) ==
        OE_ALREADY_EXISTS);
    OE_TEST(oe_register_attester_plugin(&mock_attester2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_attester_plugin(&mock_attester1, NULL, 0) ==
        OE_ALREADY_EXISTS);
    OE_TEST(
        oe_register_attester_plugin(&mock_attester2, NULL, 0) ==
        OE_ALREADY_EXISTS);
}

#endif // OE_BUILD_ENCLAVE

static void _test_and_register_verifier()
{
    printf("====== running _test_and_register_verifier\n");
    OE_TEST(oe_register_verifier_plugin(&mock_verifier1, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_verifier_plugin(&mock_verifier1, NULL, 0) ==
        OE_ALREADY_EXISTS);
    OE_TEST(oe_register_verifier_plugin(&mock_verifier2, NULL, 0) == OE_OK);
    OE_TEST(
        oe_register_verifier_plugin(&mock_verifier1, NULL, 0) ==
        OE_ALREADY_EXISTS);
    OE_TEST(
        oe_register_verifier_plugin(&mock_verifier2, NULL, 0) ==
        OE_ALREADY_EXISTS);
}

#ifdef OE_BUILD_ENCLAVE

static void _test_and_unregister_attester()
{
    printf("====== running _test_and_unregister_attester\n");
    OE_TEST(oe_unregister_attester_plugin(&mock_attester1) == OE_OK);
    OE_TEST(oe_unregister_attester_plugin(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester_plugin(&mock_attester2) == OE_OK);
    OE_TEST(oe_unregister_attester_plugin(&mock_attester1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_attester_plugin(&mock_attester2) == OE_NOT_FOUND);
}

#endif // OE_BUILD_ENCLAVE

static void _test_and_unregister_verifier()
{
    printf("====== running _test_and_unregister_verifier\n");
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier1) == OE_OK);
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier2) == OE_OK);
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier1) == OE_NOT_FOUND);
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier2) == OE_NOT_FOUND);
}

#ifdef OE_BUILD_ENCLAVE

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

    OE_TEST_CODE(
        oe_get_evidence(
            format_id,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            use_endorsements ? &endorsements : NULL,
            use_endorsements ? &endorsements_size : NULL),
        OE_OK);

    OE_TEST_CODE(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_OK);

    OE_TEST(_check_claims(claims, claims_length));

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    OE_TEST(oe_free_claims(claims, claims_length) == OE_OK);
}

static void _test_get_evidence_fail()
{
    printf("====== running _test_get_evidence_fail\n");

    uint8_t* evidence;
    size_t evidence_size;

    // Test get_evidence when plugin is unregistered.
    OE_TEST(oe_unregister_attester_plugin(&mock_attester1) == OE_OK);

    OE_TEST(
        oe_get_evidence(
            &mock_attester1.base.format_id,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            NULL) == OE_NOT_FOUND);
    OE_TEST(oe_register_attester_plugin(&mock_attester1, NULL, 0) == OE_OK);
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
            &mock_attester1.base.format_id,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
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
            NULL,
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
            NULL,
            evidence,
            evidence_size - 1,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_INVALID_PARAMETER);

    OE_TEST(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            endorsements,
            0,
            NULL,
            0,
            &claims,
            &claims_length) == OE_INVALID_PARAMETER);

    OE_TEST(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size - 1,
            NULL,
            0,
            &claims,
            &claims_length) == OE_INVALID_PARAMETER);

    // Test verify evidence when plugin is unregistered
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier1) == OE_OK);
    OE_TEST(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_NOT_FOUND);
    OE_TEST(oe_register_verifier_plugin(&mock_verifier1, NULL, 0) == OE_OK);

    // Test verify when evidence / endorsement id don't match
    uint8_t* evidence2;
    size_t evidence2_size;
    uint8_t* endorsements2;
    size_t endorsements2_size;
    oe_claim_t* claims2;
    size_t claims2_length;

    OE_TEST_CODE(
        oe_get_evidence(
            &mock_attester2.base.format_id,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &evidence2,
            &evidence2_size,
            &endorsements2,
            &endorsements2_size),
        OE_OK);

    OE_TEST_CODE(
        oe_verify_evidence(
            NULL,
            evidence2,
            evidence2_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims2,
            &claims2_length),
        OE_CONSTRAINT_FAILED);

    OE_TEST(oe_free_evidence(evidence2) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements2) == OE_OK);

    // Test faulty verifier when they don't have the right claims.
    OE_TEST(oe_unregister_verifier_plugin(&mock_verifier1) == OE_OK);
    OE_TEST(oe_register_verifier_plugin(&bad_verifier, NULL, 0) == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_length) == OE_CONSTRAINT_FAILED);

    OE_TEST(oe_unregister_verifier_plugin(&bad_verifier) == OE_OK);
    OE_TEST(oe_register_verifier_plugin(&mock_verifier1, NULL, 0) == OE_OK);
    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

#endif // OE_BUILD_ENCLAVE

void test_runtime()
{
#ifdef OE_BUILD_ENCLAVE
    printf("====== running test_runtime, enclave side\n");

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
#else
    printf("====== running test_runtime, host side, only verifier tests\n");
    // Test register functions.
    _test_and_register_verifier();

    // Test unregister functions
    _test_and_unregister_verifier();
#endif
}

void register_verifier()
{
    oe_uuid_t* formats = NULL;
    size_t formats_length = 0;

    OE_TEST_CODE(oe_verifier_initialize(), OE_OK);
    OE_TEST_CODE(oe_verifier_get_formats(&formats, &formats_length), OE_OK);
    OE_TEST_CODE(oe_verifier_free_formats(formats), OE_OK);
}

void unregister_verifier()
{
    OE_TEST_CODE(oe_verifier_shutdown(), OE_OK);
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

static void _process_endorsements(
    const uint8_t* endorsements,
    size_t endorsements_size,
    bool wrapped_with_header,
    const uint8_t** endorsements_body,
    size_t* endorsements_body_size)
{
    if (endorsements && wrapped_with_header)
    {
        oe_attestation_header_t* endorsements_header =
            (oe_attestation_header_t*)endorsements;

        OE_TEST(endorsements_size >= sizeof(oe_attestation_header_t));

        *endorsements_body = endorsements_header->data;
        *endorsements_body_size = endorsements_header->data_size;
    }
    else
    {
        *endorsements_body = endorsements;
        *endorsements_body_size = endorsements_size;
    }
}

static void _test_time(
    const uint8_t* report_body,
    size_t report_body_size,
    const uint8_t* collaterals,
    size_t collaterals_size,
    oe_datetime_t* from,
    oe_datetime_t* until)
{
    oe_datetime_t tmp;

    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body, report_body_size, collaterals, collaterals_size, from),
        OE_OK);

    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body,
            report_body_size,
            collaterals,
            collaterals_size,
            until),
        OE_OK);

    tmp = *from;
    tmp.year--;
    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body, report_body_size, collaterals, collaterals_size, &tmp),
        OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

    tmp = *until;
    tmp.year++;
    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body, report_body_size, collaterals, collaterals_size, &tmp),
        OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);
}

static void _test_time_policy(
    const oe_uuid_t* format_id,
    bool wrapped_with_header,
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
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size),
        OE_OK);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);

    dt = *until;
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size),
        OE_OK);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);

    dt = *from;
    dt.year--;
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size),
        OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

    dt = *until;
    dt.year++;
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            &policy,
            1,
            &claims,
            &claims_size),
        OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);
}

static const oe_uuid_t _local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _ecdsa_report_uuid = {
    OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};
static const oe_uuid_t _ecdsa_quote_uuid = {OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};

void verify_sgx_evidence(
    const oe_uuid_t* format_id,
    bool wrapped_with_header,
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    const uint8_t* expected_endorsements,
    size_t expected_endorsements_size,
    const uint8_t* custom_claims_buffer,
    size_t custom_claims_buffer_size)
{
    printf("running verify_sgx_evidence\n");

    oe_attestation_header_t* evidence_header =
        (oe_attestation_header_t*)evidence;
    oe_report_t report;
    oe_claim_t* claims = NULL;
    size_t claims_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;
    void* value;
    void* from;
    void* until;
    bool is_local;

    sgx_evidence_format_type_t format_type = SGX_FORMAT_TYPE_UNKNOWN;
    const uint8_t* report_body = NULL;
    size_t report_body_size = 0;
    const uint8_t* endorsements_body = NULL;
    size_t endorsements_body_size = 0;

    OE_TEST(evidence && evidence_size);

    if (!format_id)
    {
        OE_TEST(evidence_size >= sizeof(*evidence_header));
        format_id = &evidence_header->format_id;
    }

    if (!memcmp(format_id, &_local_uuid, sizeof(oe_uuid_t)))
    {
        // evidence might be prefixed with oe_attestation_header_t
        // but not with oe_report_header_t
        if (wrapped_with_header)
        {
            OE_TEST(evidence_size > sizeof(oe_attestation_header_t));
            report_body = evidence_header->data;
        }
        else
            report_body = evidence;

        report_body_size = sizeof(sgx_report_t);

        format_type = SGX_FORMAT_TYPE_LOCAL;
        is_local = true;
    }
    else if (!memcmp(format_id, &_ecdsa_uuid, sizeof(oe_uuid_t)))
    {
        // evidence might be prefixed with oe_attestation_header_t
        // but not with oe_report_header_t
        if (wrapped_with_header)
        {
            OE_TEST(evidence_size > sizeof(oe_attestation_header_t));
            report_body = evidence_header->data;
        }
        else
            report_body = evidence;

        report_body_size =
            sizeof(sgx_quote_t) + ((sgx_quote_t*)report_body)->signature_len;

        format_type = SGX_FORMAT_TYPE_REMOTE;
        is_local = false;
    }
    else if (!memcmp(format_id, &_ecdsa_report_uuid, sizeof(oe_uuid_t)))
    {
        // evidence_buffer has oe_report_header_t
        oe_report_header_t* report = (oe_report_header_t*)evidence;

        OE_TEST(evidence_size >= sizeof(oe_report_header_t));

        OE_TEST(
            report->version == OE_REPORT_HEADER_VERSION &&
            report->report_type == OE_REPORT_TYPE_SGX_REMOTE);

        format_type = SGX_FORMAT_TYPE_LEGACY_REPORT;
        report_body = report->report;
        report_body_size = report->report_size;
        is_local = false;
    }
    else if (!memcmp(format_id, &_ecdsa_quote_uuid, sizeof(oe_uuid_t)))
    {
        format_type = SGX_FORMAT_TYPE_RAW_QUOTE;
        report_body = evidence;
        report_body_size = evidence_size;
        is_local = false;
    }
    else
        OE_TEST_CODE(OE_INVALID_PARAMETER, OE_OK);

    // Parse into SGX endorsements to validate endorsements related claims.
    _process_endorsements(
        expected_endorsements,
        expected_endorsements_size,
        wrapped_with_header,
        &endorsements_body,
        &endorsements_body_size);
    if (endorsements_body)
    {
        OE_TEST_CODE(
            oe_parse_sgx_endorsements(
                (oe_endorsements_t*)endorsements_body,
                endorsements_body_size,
                &sgx_endorsements),
            OE_OK);
    }

    _process_endorsements(
        endorsements,
        endorsements_size,
        wrapped_with_header,
        &endorsements_body,
        &endorsements_body_size);

    // Try with no policies.
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            &claims,
            &claims_size),
        OE_OK);

    // Make sure that the identity info matches with the regular oe report.

    OE_TEST_CODE(
        oe_parse_sgx_report_body(
            (format_type == SGX_FORMAT_TYPE_LOCAL
                 ? &((sgx_report_t*)report_body)->body
                 : &((sgx_quote_t*)report_body)->report_body),
            !is_local,
            &report),
        OE_OK);

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
    value = _find_claim(claims, claims_size, OE_CLAIM_FORMAT_UUID);
    OE_TEST(value != NULL && memcmp(value, format_id, sizeof(*format_id)) == 0);

    // Check date time.
    from = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_FROM);
    OE_TEST(is_local || from != NULL);

    until = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_UNTIL);
    OE_TEST(is_local || until != NULL);

    // Check SGX endorsements related claims:
    if (expected_endorsements)
    {
        for (uint32_t i = OE_REQUIRED_CLAIMS_COUNT + OE_OPTIONAL_CLAIMS_COUNT,
                      j = 1;
             j <= OE_SGX_CLAIMS_COUNT;
             i++, j++)
        {
            value = claims[i].value;
            OE_TEST(
                value != NULL && memcmp(
                                     value,
                                     sgx_endorsements.items[j].data,
                                     sgx_endorsements.items[j].size) == 0);
        }
    }

    if (endorsements)
    {
        _test_time(
            report_body,
            report_body_size,
            endorsements_body,
            endorsements_body_size,
            (oe_datetime_t*)from,
            (oe_datetime_t*)until);

        _test_time_policy(
            format_id,
            wrapped_with_header,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            (oe_datetime_t*)from,
            (oe_datetime_t*)until);
    }

    // Check custom claims.
    // For SGX report or quote, this is captured in SGX report data.
    if (custom_claims_buffer)
    {
        if (format_type == SGX_FORMAT_TYPE_LOCAL ||
            format_type == SGX_FORMAT_TYPE_REMOTE)
            value =
                _find_claim(claims, claims_size, OE_CLAIM_CUSTOM_CLAIMS_BUFFER);
        else
            value = _find_claim(claims, claims_size, OE_CLAIM_SGX_REPORT_DATA);
        OE_TEST(
            value != NULL &&
            !memcmp(custom_claims_buffer, value, custom_claims_buffer_size));
    }
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
    claims = NULL;
    claims_size = 0;

    // Test SGX evidence verification using tampered-with custom claims.
    // Doable only when non-empty custom claims data is present
    if (custom_claims_buffer && (format_type == SGX_FORMAT_TYPE_LOCAL ||
                                 format_type == SGX_FORMAT_TYPE_REMOTE))
    {
        printf("running verify_sgx_evidence failed with hampered claims\n");

        // Tamper with the last byte of the custom claims data.
        evidence_header->data[evidence_header->data_size - 1] ^= 1;

        OE_TEST(
            oe_verify_evidence(
                wrapped_with_header ? NULL : format_id,
                evidence,
                evidence_size,
                endorsements,
                endorsements_size,
                NULL,
                0,
                &claims,
                &claims_size) == OE_QUOTE_HASH_MISMATCH);

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;

        evidence_header->data[evidence_header->data_size - 1] ^= 1;
    }

    // Test SGX evidence verification with wrong attestation header flag.
    // For evidence with attestation header, the format_id parameter for
    // oe_verify_evidence() should be NULL.
    if (wrapped_with_header &&
        !memcmp(format_id, &_ecdsa_uuid, sizeof(oe_uuid_t)))
    {
        printf("running verify_sgx_evidence failed on treating evidence "
               "wrapped_with_header as not\n");

        // The plugin for the given format_id shall not be able to verify the
        // evidence, but the error code is plugin specific.
        OE_TEST(
            oe_verify_evidence(
                format_id,
                evidence,
                evidence_size,
                endorsements,
                endorsements_size,
                NULL,
                0,
                &claims,
                &claims_size) != OE_OK);

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;
    }

    // Extract legacy OE report and SGX quote from ECDSA evidence
    // and verify them using the conrresponding legacy format IDs.
    // Accompanied endorsements data (wrappwed with a header) is dropped
    if (wrapped_with_header &&
        !memcmp(format_id, &_ecdsa_uuid, sizeof(oe_uuid_t)))
    {
        oe_result_t result;
        oe_attestation_header_t* evidence_header =
            (oe_attestation_header_t*)evidence;
        const sgx_quote_t* quote = (sgx_quote_t*)evidence_header->data;
        size_t quote_size = sizeof(*quote) + quote->signature_len;
        uint8_t* report_buffer = NULL;
        size_t report_buffer_size = sizeof(oe_report_header_t) + quote_size;
        OE_SHA256 hash;

        printf(
            "running verify_sgx_evidence on extracted OE_report / SGX_quote\n");

        OE_TEST_CODE(
            oe_sgx_hash_custom_claims_buffer(
                custom_claims_buffer, custom_claims_buffer_size, &hash),
            OE_OK);

        report_buffer = (uint8_t*)oe_malloc(report_buffer_size);
        OE_TEST(report_buffer != NULL);
        { // Create a temporary buffer with OE report for SGX remote attestation
            oe_report_header_t* report_header =
                (oe_report_header_t*)report_buffer;
            report_header->version = OE_REPORT_HEADER_VERSION;
            report_header->report_type = OE_REPORT_TYPE_SGX_REMOTE;
            report_header->report_size = quote_size;
            memcpy(report_header->report, quote, quote_size);
        }

        OE_TEST_CODE(
            oe_verify_evidence(
                &_ecdsa_report_uuid,
                report_buffer,
                report_buffer_size,
                NULL,
                0,
                NULL,
                0,
                &claims,
                &claims_size),
            OE_OK);

        oe_free(report_buffer);
        report_buffer = NULL;

        value = _find_claim(claims, claims_size, OE_CLAIM_SGX_REPORT_DATA);

        OE_TEST(value != NULL && !memcmp(&hash, value, sizeof(hash)));

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;

        OE_TEST_CODE(
            oe_verify_evidence(
                &_ecdsa_quote_uuid,
                (const uint8_t*)quote,
                quote_size,
                NULL,
                0,
                NULL,
                0,
                &claims,
                &claims_size),
            OE_OK);

        value = _find_claim(claims, claims_size, OE_CLAIM_SGX_REPORT_DATA);

        OE_TEST(value != NULL && !memcmp(&hash, value, sizeof(hash)));

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;

        printf("running verify_sgx_evidence failed on OE_report treated as "
               "wrapped_with_header\n");

        // oe_verify_evidence() shall fail header check or not be able to
        // find a plugin, since the evidence has no valid attestation header.
        result = oe_verify_evidence(
            NULL,
            (const uint8_t*)quote,
            quote_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_size);
        OE_TEST(result == OE_INVALID_PARAMETER || result == OE_NOT_FOUND);

        // With failed oe_verify_evidence(), no claims are returned.

        printf("done verify_sgx_evidence on OE_report / SGX_quote\n");
    }
}
