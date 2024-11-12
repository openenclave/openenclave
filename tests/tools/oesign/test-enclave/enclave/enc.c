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
#include "oesign_test_t.h"

/* Null-terminated hex string buffer size with 2 char per byte */
#define OE_KSS_ID_HEX_BUFFER_SIZE (sizeof(oe_uuid_t) * 2 + 1)
/* Null-terminated hex string buffer size with 2 char per byte and 4 formatting
 * chars */
#define FORMATTED_OE_KSS_ID_HEX_BUFFER_SIZE (OE_KSS_ID_HEX_BUFFER_SIZE + 4)

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

bool is_test_signed()
{
    static const uint8_t OE_DEFAULT_DEBUG_SIGNED_MRSIGNER[] = {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
        0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
        0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

    bool is_test_signed = false;
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* report_data = NULL;
    size_t report_size = 0;
    oe_report_t report;
    const size_t mrsigner_hex_length =
        sizeof(report.identity.signer_id) * 2 + 1;
    char mrsigner_hex[mrsigner_hex_length];

    OE_STATIC_ASSERT(
        sizeof(OE_DEFAULT_DEBUG_SIGNED_MRSIGNER) ==
        sizeof(report.identity.signer_id));

    result = oe_get_report(0, NULL, 0, NULL, 0, &report_data, &report_size);
    if (result == OE_OK)
    {
        result = oe_parse_report(report_data, report_size, &report);
        if (result == OE_OK)
        {
            oe_hex_string(
                mrsigner_hex,
                mrsigner_hex_length,
                report.identity.signer_id,
                sizeof(report.identity.signer_id));

            printf("Enclave MRSIGNER = %s\n", mrsigner_hex);

            is_test_signed =
                (memcmp(
                     report.identity.signer_id,
                     OE_DEFAULT_DEBUG_SIGNED_MRSIGNER,
                     sizeof(report.identity.signer_id)) != 0);
        }

        oe_free_report(report_data);
    }

    return is_test_signed;
}

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

void formatted_string_from_uuid(
    uint8_t* uuid,
    size_t uuid_size,
    char* formatted_string,
    size_t formatted_string_size)
{
    // Release builds may optimize the oe_assert statement involving
    // formatted_string_size away
    OE_UNUSED(formatted_string_size);

    // Expect the formatted_str_id size to be
    // FORMATTED_OE_KSS_ID_HEX_BUFFER_SIZE
    oe_assert(formatted_string_size == FORMATTED_OE_KSS_ID_HEX_BUFFER_SIZE);

    char unformatted_string[OE_KSS_ID_HEX_BUFFER_SIZE] = {0};

    oe_hex_string(
        unformatted_string, OE_KSS_ID_HEX_BUFFER_SIZE, uuid, uuid_size);

    size_t i;
    size_t k;
    for (i = k = 0; k < OE_KSS_ID_HEX_BUFFER_SIZE; i++, k++)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            formatted_string[i++] = '-';
        formatted_string[i] = unformatted_string[k];
    }
}

oe_result_t check_kss_extended_ids(
    oe_uuid_t* family_id,
    oe_uuid_t* extended_product_id)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_header_t* header = NULL;
    sgx_quote_t* quote = NULL;

    char formatted_isvid_hex[FORMATTED_OE_KSS_ID_HEX_BUFFER_SIZE];

    printf("========== Getting report with KSS feature\n");

    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        0,
        NULL,
        0,
        (uint8_t**)&remote_report,
        &report_size);

    if (result == OE_OK)
    {
        printf("========== Got report, size = %zu\n", report_size);

        header = (oe_report_header_t*)remote_report;
        quote = (sgx_quote_t*)header->report;

        sgx_report_body_t* report_body =
            (sgx_report_body_t*)&quote->report_body;

        formatted_string_from_uuid(
            report_body->isvfamilyid,
            sizeof(report_body->isvfamilyid),
            formatted_isvid_hex,
            sizeof(formatted_isvid_hex));

        OE_TRACE_INFO(
            "Enclave ISV Family ID from report = %s\n", formatted_isvid_hex);

        formatted_string_from_uuid(
            report_body->isvextprodid,
            sizeof(report_body->isvextprodid),
            formatted_isvid_hex,
            sizeof(formatted_isvid_hex));

        OE_TRACE_INFO(
            "Enclave ISV Extended ProductID from report = %s\n",
            formatted_isvid_hex);

        if (memcmp(report_body->isvfamilyid, family_id, sizeof(oe_uuid_t)) ||
            memcmp(
                report_body->isvextprodid,
                extended_product_id,
                sizeof(oe_uuid_t)))
            result = OE_REPORT_PARSE_ERROR;
    }

    // Use updated APIs
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    printf("========== Getting evidence with KSS feature\n");

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

    oe_uuid_t* is_v_family_id_value;
    oe_uuid_t* is_v_ext_prod_id_value;
    is_v_family_id_value = (oe_uuid_t*)_find_claim(
        claims, claims_length, OE_CLAIM_SGX_ISV_FAMILY_ID);
    is_v_ext_prod_id_value = (oe_uuid_t*)_find_claim(
        claims, claims_length, OE_CLAIM_SGX_ISV_EXTENDED_PRODUCT_ID);

    formatted_string_from_uuid(
        (uint8_t*)is_v_family_id_value,
        sizeof(oe_uuid_t),
        formatted_isvid_hex,
        sizeof(formatted_isvid_hex));

    OE_TRACE_INFO(
        "Enclave ISV Family ID from evidence = %s", formatted_isvid_hex);

    formatted_string_from_uuid(
        (uint8_t*)is_v_ext_prod_id_value,
        sizeof(oe_uuid_t),
        formatted_isvid_hex,
        sizeof(formatted_isvid_hex));

    OE_TRACE_INFO(
        "Enclave ISV Extended ProductID from evidence = %s",
        formatted_isvid_hex);

    if (memcmp(is_v_family_id_value, family_id, sizeof(oe_uuid_t)) ||
        memcmp(is_v_ext_prod_id_value, extended_product_id, sizeof(oe_uuid_t)))
        result = OE_REPORT_PARSE_ERROR;

done:
    oe_free_report(remote_report);
    OE_CHECK(oe_free_evidence(evidence));
    OE_CHECK(oe_free_claims(claims, claims_length));
    OE_CHECK(oe_attester_shutdown());
    OE_CHECK(oe_verifier_shutdown());

    return result;
}
