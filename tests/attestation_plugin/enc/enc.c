// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <string.h>

#include "../../../common/attest_plugin.h"
#include "../../../common/sgx/quote.h"
#include "../plugin/tests.h"
#include "plugin_t.h"

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
static const oe_uuid_t _local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static const oe_uuid_t _epid_linkable_uuid = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

static const oe_uuid_t* _lifetime_formats[] = {
    &_local_uuid,
    &_ecdsa_uuid,
    &_epid_linkable_uuid,
    &_epid_unlinkable_uuid};
static oe_attester_t* _lifetime_plugins[OE_COUNTOF(_lifetime_formats)];

static oe_result_t _paused_get_report(
    oe_attester_t* context,
    uint32_t flags,
    const uint8_t* report_data,
    size_t report_data_size,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size)
{
    OE_UNUSED(context);
    OE_UNUSED(flags);
    OE_UNUSED(report_data);
    OE_UNUSED(report_data_size);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    OE_UNUSED(report_buffer);
    OE_UNUSED(report_buffer_size);
    OE_TEST(pause_report_dispatch() == OE_OK);
    return OE_FAILURE;
}

void test_report_lifetime()
{
    oe_attester_t* plugin = NULL;
    uint8_t* report = NULL;
    size_t report_size = 0;
    OE_TEST(oe_attester_initialize() == OE_OK);
    for (size_t i = 0; i < OE_COUNTOF(_lifetime_formats); ++i)
    {
        oe_result_t result = oe_find_attester_plugin(
            _lifetime_formats[i], &_lifetime_plugins[i]);
        OE_TEST(result == OE_OK || result == OE_NOT_FOUND);
    }
    OE_TEST(oe_find_attester_plugin(&_local_uuid, &plugin) == OE_OK);

    // Pause the real report API inside its callback, with its reference held.
    oe_result_t (*get_report)(
        oe_attester_t*,
        uint32_t,
        const uint8_t*,
        size_t,
        const void*,
        size_t,
        uint8_t**,
        size_t*) = plugin->get_report;
    plugin->get_report = _paused_get_report;
    OE_TEST(
        oe_get_report(0, NULL, 0, NULL, 0, &report, &report_size) ==
        OE_FAILURE);
    plugin->get_report = get_report;
    OE_TEST(report == NULL);
}

void test_attester_shutdown_busy()
{
    OE_TEST(oe_attester_shutdown() == OE_BUSY);
    OE_TEST(oe_attester_initialize() == OE_OK);
    for (size_t i = 0; i < OE_COUNTOF(_lifetime_formats); ++i)
    {
        oe_attester_t* plugin = NULL;
        if (!_lifetime_plugins[i])
            continue;
        OE_TEST(
            oe_acquire_attester_plugin(_lifetime_formats[i], &plugin) == OE_OK);
        OE_TEST(plugin == _lifetime_plugins[i]);
        oe_release_attester_plugin();
        OE_TEST(oe_unregister_attester_plugin(plugin) == OE_BUSY);
    }
    OE_TEST(oe_verifier_initialize() == OE_OK);
    OE_TEST(oe_verifier_shutdown() == OE_OK);
}

void test_attester_shutdown_after_release()
{
    OE_TEST(oe_attester_shutdown() == OE_OK);
    OE_TEST(oe_attester_initialize() == OE_OK);
    OE_TEST(oe_attester_shutdown() == OE_OK);
}

void run_runtime_test()
{
    printf("====== running run_runtime_test\n");
    test_runtime();
}

void register_sgx()
{
    printf("====== running register_sgx\n");

    OE_TEST_CODE(oe_attester_initialize(), OE_OK);
    register_verifier();
}

void unregister_sgx()
{
    printf("====== running unregister_sgx\n");

    OE_TEST_CODE(oe_attester_shutdown(), OE_OK);
    unregister_verifier();
}

void test_pck_crl_validation(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size)
{
    /*
     * Test that both hex encoded (sgx pccs v3) and RAW encode (sgx pccs v3.1)
     * der pckcrl are processed by oe_validate_revocation_list().
     */

    printf("====== running test_pck_crl_validation \n");
    validate_sgx_pck_crl(
        evidence, evidence_size, endorsements, endorsements_size);
}

static void _test_sgx_remote()
{
    printf("====== running _test_sgx_remote\n");
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements = NULL;
    size_t endorsements_size = 0;
    oe_uuid_t selected_format;

    OE_TEST_CODE(
        oe_attester_select_format(&_ecdsa_uuid, 1, &selected_format), OE_OK);

    // Get evidence.
    printf("====== running _test_sgx_remote #1: Just evidence\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            NULL,
            0),
        OE_OK);

    printf("evidence_size=%d\n", evidence_size);

    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;

    // Get evidence with endorsements.
    printf("====== running _test_sgx_remote #2: + Endorsements\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &selected_format,
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

    printf(
        "evidence_size=%d endorsements_size=%d\n",
        evidence_size,
        endorsements_size);

    printf("verify evidence by passing NULL endorsements\n");
    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        NULL, // endorsements
        0,
        endorsements, // expected_endorsements
        endorsements_size,
        NULL,
        0);

    printf("verify evidence by passing non-NULL endorsements\n");
    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        endorsements, // expected_endorsements
        endorsements_size,
        NULL,
        0);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    endorsements = NULL;

    // Get a remote report with both.
    printf("====== running _test_sgx_remote #3: + Claims\n");
    printf("testing a 64-byte custom claims\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            test_claims,
            TEST_CLAIMS_SIZE,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size),
        OE_OK);

    printf(
        "evidence_size=%d endorsements_size=%d claims_length=%d\n",
        evidence_size,
        endorsements_size,
        TEST_CLAIMS_SIZE);

    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        endorsements,
        endorsements_size,
        test_claims,
        TEST_CLAIMS_SIZE);

    printf("using host_verify()\n");
    OE_TEST(
        host_verify(
            &selected_format,
            true,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size) == OE_OK);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    endorsements = NULL;

    printf("testing a 65-byte custom claims\n");
    OE_TEST_CODE(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            test_large_claims,
            TEST_LARGE_CLAIMS_SIZE,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size),
        OE_OK);

    printf(
        "evidence_size=%d endorsements_size=%d claims_length=%d\n",
        evidence_size,
        endorsements_size,
        TEST_LARGE_CLAIMS_SIZE);

    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        endorsements,
        endorsements_size,
        test_large_claims,
        TEST_LARGE_CLAIMS_SIZE);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;
    // Note: endorsements are reused in testing legacy report / quote
    // In those tests, the prefixed attestation header is ignored.

    printf("verifying OE_report generated by oe_get_report()\n");

    OE_TEST_CODE(
        oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            test_claims, // place custom claims in sgx report data
            TEST_CLAIMS_SIZE,
            NULL,
            0,
            (uint8_t**)&evidence,
            &evidence_size),
        OE_OK);

    {
        static const oe_uuid_t _ecdsa_report_uuid = {
            OE_FORMAT_UUID_LEGACY_REPORT_REMOTE};
        verify_sgx_evidence(
            &_ecdsa_report_uuid,
            false,
            evidence,
            evidence_size,
            NULL,
            0,
            endorsements + sizeof(oe_attestation_header_t),
            endorsements_size - sizeof(oe_attestation_header_t),
            test_claims,
            TEST_CLAIMS_SIZE);
    }

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;

    printf("verifying SGX quote extracted from OE_report\n");

    OE_TEST_CODE(
        oe_get_report(
            OE_REPORT_FLAGS_REMOTE_ATTESTATION,
            test_claims, // place custom claims in sgx report data
            TEST_CLAIMS_SIZE,
            NULL,
            0,
            (uint8_t**)&evidence,
            &evidence_size),
        OE_OK);

    {
        static const oe_uuid_t _ecdsa_quote_uuid = {
            OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA};
        verify_sgx_evidence(
            &_ecdsa_quote_uuid,
            false,
            // offset OE_report by oe_report_header_t to get OE_report.report
            // which is an SGX quote
            evidence + sizeof(oe_report_header_t),
            evidence_size - sizeof(oe_report_header_t),
            NULL,
            0,
            endorsements + sizeof(oe_attestation_header_t),
            endorsements_size - sizeof(oe_attestation_header_t),
            test_claims,
            TEST_CLAIMS_SIZE);
    }

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
    endorsements = NULL;

    if (oe_attester_select_format(&_epid_linkable_uuid, 1, &selected_format) ==
        OE_OK)
    {
        uint8_t spid[16] = "SPID";

        printf("====== running _test_sgx_remote #4: get EPID evidence\n");

        OE_TEST_CODE(
            oe_get_evidence(
                &_epid_linkable_uuid,
                0,
                NULL,
                0,
                NULL,
                0,
                &evidence,
                &evidence_size,
                &endorsements,
                &endorsements_size),
            OE_OK);
        OE_TEST(oe_free_evidence(evidence) == OE_OK);
        evidence = NULL;
        OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
        endorsements = NULL;

        OE_TEST_CODE(
            oe_get_evidence(
                &_epid_unlinkable_uuid,
                0,
                NULL,
                0,
                spid,
                sizeof(spid),
                &evidence,
                &evidence_size,
                &endorsements,
                &endorsements_size),
            OE_OK);
        OE_TEST(oe_free_evidence(evidence) == OE_OK);
        evidence = NULL;
        OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
        endorsements = NULL;

        OE_TEST_CODE(
            oe_get_evidence(
                &_epid_unlinkable_uuid,
                0,
                NULL,
                0,
                spid,
                1,
                &evidence,
                &evidence_size,
                &endorsements,
                &endorsements_size),
            OE_INVALID_PARAMETER);
    }
    else
        printf("====== note: _test_sgx_remote #4: EPID not supported\n");

    printf("====== done _test_sgx_remote\n");
}

static void _test_sgx_local()
{
    uint8_t* target = NULL;
    size_t target_size = 0;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    oe_uuid_t selected_format;

    printf("====== running _test_sgx_local\n");

    OE_TEST_CODE(
        oe_attester_select_format(&_local_uuid, 1, &selected_format), OE_OK);

    printf("====== running _test_sgx_local #0: Getting target info.\n");
    OE_TEST(
        oe_verifier_get_format_settings(
            &selected_format, &target, &target_size) == OE_OK);

    // Only evidence.
    printf("====== running _test_sgx_local #1: Just evidence\n");
    OE_TEST(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);

    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;

    // Evidence + claims.
    printf("====== running _test_sgx_local #2: + Claims\n");
    OE_TEST(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            test_claims,
            TEST_CLAIMS_SIZE,
            target,
            target_size,
            &evidence,
            &evidence_size,
            NULL,
            0) == OE_OK);

    verify_sgx_evidence(
        &selected_format,
        true,
        evidence,
        evidence_size,
        NULL,
        0,
        NULL,
        0,
        test_claims,
        TEST_CLAIMS_SIZE);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    evidence = NULL;
    oe_verifier_free_format_settings(target);
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
    true, /* Debug */
    1024, /* NumHeapPages */
    128,  /* NumStackPages */
    2);   /* NumTCS */
