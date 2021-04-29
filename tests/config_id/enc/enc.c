// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "../common.h"
#include "config_id_t.h"

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

static void* _find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        // Claim names are case sensitive.
        if (strcmp(claims[i].name, name) == 0)
            return claims[i].value;
    }
    return NULL;
}

oe_result_t enclave_test_config_id()
{
    OE_TRACE_INFO("enclave_config_id_test_kss_properties invoked\n");

    oe_result_t result = OE_OK;
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_TRACE_ERROR("========== Getting evidence with KSS feature\n");

    OE_CHECK(oe_attester_initialize());

    oe_uuid_t selected_format;
    oe_attester_select_format(&_ecdsa_uuid, 1, &selected_format);

    OE_CHECK(oe_get_evidence(
        &selected_format,
        OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
        NULL,
        0,
        NULL,
        0,
        &evidence,
        &evidence_size,
        NULL,
        0));

    OE_CHECK(oe_verifier_initialize());

    OE_CHECK(oe_verify_evidence(
        NULL,
        evidence,
        evidence_size,
        NULL,
        0,
        NULL,
        0,
        &claims,
        &claims_length));

    uint8_t* config_id;
    uint16_t* config_svn;

    config_id =
        (uint8_t*)_find_claim(claims, claims_length, OE_CLAIM_SGX_CONFIG_ID);

    config_svn =
        (uint16_t*)_find_claim(claims, claims_length, OE_CLAIM_SGX_CONFIG_SVN);

    if (memcmp(config_id, original_config_id, sizeof(original_config_id)))
    {
        OE_TRACE_INFO("\noriginal_config_id :\n0x");
        oe_hex_dump(original_config_id, OE_COUNTOF(original_config_id));
        OE_TRACE_INFO("\nparsed config_id :\n0x");
        oe_hex_dump(config_id, OE_COUNTOF(original_config_id));
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "========== Read wrong config id from the report");
    }

    if (memcmp(config_svn, &original_config_svn, sizeof(original_config_svn)))
    {
        OE_RAISE_MSG(
            OE_REPORT_PARSE_ERROR,
            "========== Read wrong config svn(0x%x) from the report, "
            "expected(0x%x)",
            *config_svn,
            original_config_svn);
    }

done:
    oe_free_evidence(evidence);
    oe_free_claims(claims, claims_length);
    oe_attester_shutdown();
    oe_verifier_shutdown();
    return result;
}

oe_result_t enclave_test_config_id_non_kss()
{
    OE_TRACE_INFO("enclave function invoked on non kss image\n");
    return OE_OK;
}
