// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openenclave/bits/evidence.h"
#include "openenclave/bits/result.h"
#include "openenclave/internal/safecrt.h"
#ifdef OE_BUILD_ENCLAVE
#include <openenclave/attestation/attester.h>
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <ctype.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/crypto/cert.h>
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
#include "../../../host/sgx/sgxquoteprovider.h"
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

static void _find_fmspc(uint8_t* tcb_info, uint8_t* fmspc, size_t fmspc_size)
{
    char* substr = "fmspc";
    char* p_fmspc;
    long data = 0;
    char hex[3];

    p_fmspc = strstr((char*)tcb_info, substr);
    p_fmspc = p_fmspc + 8; // move pointer to start of value
    hex[2] = '\0';

    for (size_t i = 0; i < fmspc_size; ++i)
    {
        hex[0] = *p_fmspc++;
        hex[1] = *p_fmspc++;

        data = strtol(hex, NULL, 16);
        *(fmspc + i) = (uint8_t)data;
    }
}

static void _test_claims(
    const oe_claim_t* claims,
    size_t claims_size,
    sgx_evidence_format_type_t format_type,
    bool is_local,
    bool tcb_level_valid,
    const uint8_t* report_body,
    const oe_uuid_t* format_id,
    const oe_sgx_endorsements_t* sgx_endorsements,
    const uint8_t* custom_claims_buffer,
    size_t custom_claims_buffer_size)
{
    oe_report_t report;
    const sgx_report_body_t* sgx_report_body;
    void* value;
    bool flag;

    // Check SGX report identity and OE claims
    sgx_report_body = format_type == SGX_FORMAT_TYPE_LOCAL
                          ? &((sgx_report_t*)report_body)->body
                          : &((sgx_quote_t*)report_body)->report_body;

    // Make sure that the identity info matches with the regular oe report.
    OE_TEST_CODE(
        oe_parse_sgx_report_body(sgx_report_body, !is_local, &report), OE_OK);

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

    // Check SGX Page Fault, General Protection Exception Reported to an SSA
    // Frame or Not
    flag = !!(sgx_report_body->miscselect & SGX_MISC_FLAGS_PF_GP_EXIT_INFO);
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_PF_GP_EXINFO_ENABLED);
    OE_TEST(value != NULL && memcmp(value, &flag, sizeof(flag)) == 0);

    // Check SGX Report ISV Extended Product ID
    value =
        _find_claim(claims, claims_size, OE_CLAIM_SGX_ISV_EXTENDED_PRODUCT_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             sgx_report_body->isvextprodid,
                             sizeof(sgx_report_body->isvextprodid)) == 0);

    // Check whether the SGX Report is Mode 64bit or not.
    flag = !!(sgx_report_body->attributes.flags & SGX_FLAGS_MODE64BIT);
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_IS_MODE64BIT);
    OE_TEST(value != NULL && memcmp(value, &flag, sizeof(flag)) == 0);

    // Check SGX Report Has Provision Key or Not
    flag = !!(sgx_report_body->attributes.flags & SGX_FLAGS_PROVISION_KEY);
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_HAS_PROVISION_KEY);
    OE_TEST(value != NULL && memcmp(value, &flag, sizeof(flag)) == 0);

    // Check SGX Report Has Einittoken Key or Not
    flag = !!(sgx_report_body->attributes.flags & SGX_FLAGS_EINITTOKEN_KEY);
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_HAS_EINITTOKEN_KEY);
    OE_TEST(value != NULL && memcmp(value, &flag, sizeof(flag)) == 0);

    // Check SGX Use KSS or Not
    flag = !!(sgx_report_body->attributes.flags & SGX_FLAGS_KSS);
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_USES_KSS);
    OE_TEST(value != NULL && memcmp(value, &flag, sizeof(flag)) == 0);

    // Check SGX Report Configuration ID
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_CONFIG_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             sgx_report_body->configid,
                             sizeof(sgx_report_body->configid)) == 0);

    // Check SGX Report Configuration Security Version
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_CONFIG_SVN);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             &sgx_report_body->configsvn,
                             sizeof(sgx_report_body->configsvn)) == 0);

    // Check SGX Report ISV Family ID
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_ISV_FAMILY_ID);
    OE_TEST(
        value != NULL && memcmp(
                             value,
                             sgx_report_body->isvfamilyid,
                             sizeof(sgx_report_body->isvfamilyid)) == 0);

    // Check SGX cpusvn
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_CPU_SVN);
    OE_TEST(
        value != NULL &&
        memcmp(
            value, sgx_report_body->cpusvn, sizeof(sgx_report_body->cpusvn)) ==
            0);

    // Check tcb status. If it is OE_SGX_TCB_STATUS_UP_TO_DATE or
    // OE_SGX_TCB_STATUS_SW_HARDENING_NEEDED, then oe_verify_evidence should
    // return OE_OK (tcb_level_valid is true), otherwise it should return
    // OE_TCB_LEVEL_INVALID
    value = _find_claim(claims, claims_size, OE_CLAIM_TCB_STATUS);
    OE_TEST(
        is_local ||
        (value != NULL &&
         (tcb_level_valid ==
          (*((oe_sgx_tcb_status_t*)value) == OE_SGX_TCB_STATUS_UP_TO_DATE ||
           *((oe_sgx_tcb_status_t*)value) ==
               OE_SGX_TCB_STATUS_SW_HARDENING_NEEDED))));

    // Check tcb date
    value = _find_claim(claims, claims_size, OE_CLAIM_TCB_DATE);
    OE_TEST(is_local || value != NULL);

    // Check date time. Date time testing will be performed in _test_time() and
    // _test_time_policy()
    value = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_FROM);
    OE_TEST(is_local || value != NULL);

    value = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_UNTIL);
    OE_TEST(is_local || value != NULL);

    sgx_quote_t* sgx_quote = (sgx_quote_t*)report_body;
    // Check universal entity ID
    value = _find_claim(claims, claims_size, OE_CLAIM_UEID);
    // The first byte of ueid claim is reserved for type and is not checked.
    uint8_t* ueid = (uint8_t*)value;
    OE_TEST(is_local || ueid[0] == OE_UEID_TYPE_RAND);
    OE_TEST(
        is_local ||
        memcmp(ueid + 1, sgx_quote->user_data, sizeof(sgx_quote->user_data)) ==
            0);

    // Check SGX specific optional claim PCESVN
    value = _find_claim(claims, claims_size, OE_CLAIM_SGX_PCE_SVN);
    OE_TEST(
        is_local ||
        memcmp(value, &sgx_quote->pce_svn, sizeof(sgx_quote->pce_svn)) == 0);

    if (sgx_endorsements)
    {
        // Check SGX specific optional claims that hold quote verification
        // collaterals.
        for (uint32_t i = OE_REQUIRED_CLAIMS_COUNT +
                          OE_SGX_REQUIRED_CLAIMS_COUNT +
                          OE_OPTIONAL_CLAIMS_COUNT,
                      j = 1;
             j <= OE_SGX_OPTIONAL_CLAIMS_SGX_COLLATERALS_COUNT;
             i++, j++)
        {
            value = claims[i].value;
            OE_TEST(
                value != NULL && memcmp(
                                     value,
                                     sgx_endorsements->items[j].data,
                                     sgx_endorsements->items[j].size) == 0);
        }

        // Check optional claim hardware_model
        if (!is_local)
        {
            /* Verify the fmspc value returned is as expected */
            const size_t fmspc_size = OE_SGX_FMSPC_SIZE;
            uint8_t* fmspc = (uint8_t*)malloc(fmspc_size);
            OE_TEST(fmspc != NULL);

            _find_fmspc(
                sgx_endorsements->items[OE_SGX_ENDORSEMENT_FIELD_TCB_INFO].data,
                fmspc,
                fmspc_size);
            value = _find_claim(claims, claims_size, OE_CLAIM_HARDWARE_MODEL);
            OE_TEST(value != NULL && memcmp(value, fmspc, fmspc_size) == 0);
            free(fmspc);
        }
    }

    // Check custom claims / sgx_report_data.
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
    oe_result_t result;
    oe_datetime_t tmp;

    result = oe_verify_sgx_quote(
        report_body,
        report_body_size,
        collaterals,
        collaterals_size,
        from,
        NULL);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);

    result = oe_verify_sgx_quote(
        report_body,
        report_body_size,
        collaterals,
        collaterals_size,
        until,
        NULL);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);

    tmp = *from;
    tmp.year--;
    // Avoid 2/29 in a leap year
    if (tmp.month == 2 && tmp.day == 29)
    {
        tmp.day = 28;
    }
    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body,
            report_body_size,
            collaterals,
            collaterals_size,
            &tmp,
            NULL),
        OE_VERIFY_FAILED_TO_FIND_VALIDITY_PERIOD);

    tmp = *until;
    tmp.year++;
    // Avoid 2/29 in a leap year
    if (tmp.month == 2 && tmp.day == 29)
    {
        tmp.day = 28;
    }
    OE_TEST_CODE(
        oe_verify_sgx_quote(
            report_body,
            report_body_size,
            collaterals,
            collaterals_size,
            &tmp,
            NULL),
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
    oe_result_t result;
    oe_policy_t policy;
    oe_datetime_t dt;
    oe_claim_t* claims;
    size_t claims_size;

    policy.type = OE_POLICY_ENDORSEMENTS_TIME;
    policy.policy = (void*)&dt;
    policy.policy_size = sizeof(dt);

    dt = *from;
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        &policy,
        1,
        &claims,
        &claims_size);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);

    dt = *until;
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        &policy,
        1,
        &claims,
        &claims_size);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);

    dt = *from;
    dt.year--;
    // Avoid 2/29 in a leap year
    if (dt.month == 2 && dt.day == 29)
    {
        dt.day = 28;
    }
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
    // Avoid 2/29 in a leap year
    if (dt.month == 2 && dt.day == 29)
    {
        dt.day = 28;
    }
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

static void _buffer_to_hex(
    char* hex_string,
    size_t hex_string_size,
    const uint8_t* buffer,
    const size_t buffer_size)
{
    OE_TEST(hex_string_size >= buffer_size * 2);

    const char* conversion_str = "0123456789ABCDEF";

    for (size_t i = 0; i < buffer_size; i++)
    {
        hex_string[2 * i] = conversion_str[(buffer[i] >> 4)];
        hex_string[2 * i + 1] = conversion_str[(buffer[i] & 0x0f)];
    }
}

static bool _is_hex_data(const uint8_t* raw_data, size_t raw_data_size)
{
    // Check if the data is composed of only hex digits
    bool ishex = true;
    for (size_t l = 0; l < raw_data_size; l++)
    {
        const uint8_t c = raw_data[l];
        if (!isxdigit(c))
        {
            ishex = false;
            break;
        }
    }

    return ishex;
}

/*
 * Tests oe_validate_revocation_list() when the sgx_endorsement
 * holds pckcrl as expected from sgx pccs v3.0 and v3.1.
 */
void validate_sgx_pck_crl(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size)
{
    const uint8_t* pem_pck_certificate = NULL;
    size_t pem_pck_certificate_size = 0;
    const uint8_t* report_body = NULL;
    size_t report_body_size = 0;
    uint8_t* hex_pckcrl = NULL;
    size_t hex_pckcrl_size = 0;
    oe_cert_chain_t pck_cert_chain = {0};
    oe_cert_t leaf_cert = {0};
    oe_sgx_endorsements_t sgx_endorsements;
    const uint8_t* endorsements_body = NULL;
    size_t endorsements_body_size = 0;
    oe_tcb_info_tcb_level_t platform_tcb_level = {{0}};
    oe_datetime_t validity_from = {0}, validity_until = {0};

    OE_TEST(evidence != NULL && endorsements != NULL);
    OE_TEST(evidence_size > 0 && endorsements_size > 0);

    report_body = evidence;
    report_body_size =
        sizeof(sgx_quote_t) + ((sgx_quote_t*)report_body)->signature_len;
    OE_TEST(evidence_size == report_body_size);

    // Get PCK cert chain from the quote.
    OE_TEST(
        oe_get_quote_cert_chain_internal(
            report_body,
            report_body_size,
            &pem_pck_certificate,
            &pem_pck_certificate_size,
            &pck_cert_chain) == OE_OK);

    // Fetch leaf certificate.
    OE_TEST(oe_cert_chain_get_leaf_cert(&pck_cert_chain, &leaf_cert) == OE_OK);

    _process_endorsements(
        endorsements,
        endorsements_size,
        false,
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

    /* Test with raw encoded pckcrl (pccs v3.1) */
    OE_TEST(
        oe_validate_revocation_list(
            &leaf_cert,
            (const oe_sgx_endorsements_t*)&sgx_endorsements,
            &platform_tcb_level,
            &validity_from,
            &validity_until) == OE_OK);

    // modify sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT]
    // to hex der.
    OE_TEST(
        _is_hex_data(
            sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].data,
            sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT]
                .size) == false);

    hex_pckcrl_size =
        2 * sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].size;
    hex_pckcrl = oe_malloc(hex_pckcrl_size);
    OE_TEST(hex_pckcrl != NULL);

    _buffer_to_hex(
        (char*)hex_pckcrl,
        hex_pckcrl_size,
        sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].data,
        sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].size);

    sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].data =
        hex_pckcrl;
    sgx_endorsements.items[OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT].size =
        (uint32_t)hex_pckcrl_size;

    /* Test with hex encoded pckcrl (pccs v3.0) */
    OE_TEST(
        oe_validate_revocation_list(
            &leaf_cert,
            (const oe_sgx_endorsements_t*)&sgx_endorsements,
            &platform_tcb_level,
            &validity_from,
            &validity_until) == OE_OK);

    oe_cert_free(&leaf_cert);
    oe_cert_chain_free(&pck_cert_chain);
    if (hex_pckcrl)
        oe_free(hex_pckcrl);
}

#ifndef OE_BUILD_ENCLAVE
extern oe_sgx_quote_provider_t provider;
static const char* test_custom_parameters_prefix = "mock_for_me:";
static const char* expected_custom_parameters = "custom_params_for_test";
static sgx_get_quote_verification_collateral_with_parameters_t
    origin_provider_api = NULL;
static sgx_plat_error_t
_test_sgx_get_quote_verification_collateral_with_parameters(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    const uint8_t* custom_parameters,
    const uint16_t custom_parameters_length,
    sgx_ql_qve_collateral_t** pp_quote_collateral)
{
    // If custom_param has prefix of test_custom_params_prefix, then mock logic
    // will apply.
    if (custom_parameters != NULL &&
        strlen((const char*)custom_parameters) >
            strlen(test_custom_parameters_prefix) &&
        memcmp(
            custom_parameters,
            test_custom_parameters_prefix,
            strlen(test_custom_parameters_prefix)) == 0)
    {
        const char* parameters = ((const char*)custom_parameters) +
                                 strlen(test_custom_parameters_prefix);
        if (strlen(parameters) != strlen(expected_custom_parameters) ||
            memcmp(
                parameters,
                expected_custom_parameters,
                strlen(expected_custom_parameters)) != 0)
        {
            return SGX_PLAT_ERROR_INVALID_PARAMETER;
        }
    }

    if (provider.get_sgx_quote_verification_collateral)
    {
        return provider.get_sgx_quote_verification_collateral(
            fmspc, fmspc_size, pck_ca, pp_quote_collateral);
    }

    if (origin_provider_api)
    {
        return origin_provider_api(
            fmspc,
            fmspc_size,
            pck_ca,
            custom_parameters,
            custom_parameters_length,
            pp_quote_collateral);
    }

    // This should not be reachable, but return an error as placeholder
    return SGX_PLAT_ERROR_INVALID_PARAMETER;
}

void set_up_mocks_for_host()
{
    origin_provider_api =
        provider.get_sgx_quote_verification_collateral_with_parameters;
    provider.get_sgx_quote_verification_collateral_with_parameters =
        &_test_sgx_get_quote_verification_collateral_with_parameters;
}
#endif

static void _test_endorsement_baseline(
    const oe_uuid_t* format_id,
    bool wrapped_with_header,
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size)
{
    oe_result_t result;
    oe_policy_t policies[2];
    oe_claim_t* claims;
    size_t claims_size;
    const char* bad_parameters = "mock_for_me:bad_params";
    const char* good_parameters = "mock_for_me:custom_params_for_test";

    policies[0].type = OE_POLICY_ENDORSEMENTS_BASELINE;
    policies[0].policy = (void*)good_parameters;
    policies[0].policy_size = strlen(good_parameters) + 1;

    // Test with good custom params
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        policies,
        1,
        &claims,
        &claims_size);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
    claims = NULL;
    claims_size = 0;

    // Test with bad custom params
    policies[0].type = OE_POLICY_ENDORSEMENTS_BASELINE;
    policies[0].policy = (void*)bad_parameters;
    policies[0].policy_size = strlen(bad_parameters) + 1;
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        policies,
        1,
        &claims,
        &claims_size);
    OE_TEST(result == OE_QUOTE_PROVIDER_CALL_ERROR);

    // Test without custom params, test should go through
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        &claims,
        &claims_size);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
    claims = NULL;
    claims_size = 0;

    // Test with multiple policies with OE_POLICY_ENDORSEMENTS_BASELINE and get
    // invalid parameter error
    policies[1].type = OE_POLICY_ENDORSEMENTS_BASELINE;
    policies[1].policy = (void*)good_parameters;
    policies[1].policy_size = strlen(good_parameters) + 1;
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        policies,
        2,
        &claims,
        &claims_size);
    OE_TEST(result == OE_INVALID_PARAMETER);
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

    oe_result_t result;
    oe_attestation_header_t* evidence_header =
        (oe_attestation_header_t*)evidence;
    oe_claim_t* claims = NULL;
    size_t claims_size = 0;
    oe_sgx_endorsements_t sgx_endorsements;
    void* from;
    void* until;
    bool is_local = false;
    bool tcb_level_valid;

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

    // Try with no output claims.
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        NULL,
        NULL);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);

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
            NULL),
        OE_INVALID_PARAMETER);
    OE_TEST_CODE(
        oe_verify_evidence(
            wrapped_with_header ? NULL : format_id,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size,
            NULL,
            0,
            NULL,
            &claims_size),
        OE_INVALID_PARAMETER);

    // Try with no policies.
    result = oe_verify_evidence(
        wrapped_with_header ? NULL : format_id,
        evidence,
        evidence_size,
        endorsements,
        endorsements_size,
        NULL,
        0,
        &claims,
        &claims_size);
    OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
    tcb_level_valid = (result == OE_OK);
    // Invalid tcb level does not terminate OE attestation verification. The tcb
    // level status is retrieved in OE_CLAIM_TCB_STATUS.
    if (!tcb_level_valid)
    {
        OE_TRACE_ERROR(
            "oe_verify_evidence result: %s. TCB Status: %s\n",
            oe_result_str(result),
            oe_sgx_tcb_status_str(*(oe_sgx_tcb_status_t*)_find_claim(
                claims, claims_size, OE_CLAIM_TCB_STATUS)));
    }

    _test_claims(
        claims,
        claims_size,
        format_type,
        is_local,
        tcb_level_valid,
        report_body,
        format_id,
        expected_endorsements ? &sgx_endorsements : NULL,
        custom_claims_buffer,
        custom_claims_buffer_size);

    // Test date time.
    from = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_FROM);
    until = _find_claim(claims, claims_size, OE_CLAIM_VALIDITY_UNTIL);

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

    OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
    claims = NULL;
    claims_size = 0;

    // Endorsement baseline is only valid when endorsements is null
    if (!is_local && !endorsements)
    {
        _test_endorsement_baseline(
            format_id,
            wrapped_with_header,
            evidence,
            evidence_size,
            endorsements,
            endorsements_size);
    }

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

        result = oe_verify_evidence(
            &_ecdsa_report_uuid,
            report_buffer,
            report_buffer_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_size);
        OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
        tcb_level_valid = (result == OE_OK);

        _test_claims(
            claims,
            claims_size,
            SGX_FORMAT_TYPE_LEGACY_REPORT,
            is_local,
            tcb_level_valid,
            report_body,
            &_ecdsa_report_uuid,
            expected_endorsements ? &sgx_endorsements : NULL,
            (const uint8_t*)&hash,
            sizeof(hash));

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;

        // Plugin should be able to handle legacy oe_report with NULL format id
        result = oe_verify_evidence(
            NULL,
            report_buffer,
            report_buffer_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_size);
        OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
        tcb_level_valid = (result == OE_OK);

        oe_free(report_buffer);
        report_buffer = NULL;

        _test_claims(
            claims,
            claims_size,
            SGX_FORMAT_TYPE_LEGACY_REPORT,
            is_local,
            tcb_level_valid,
            report_body,
            &_ecdsa_report_uuid,
            expected_endorsements ? &sgx_endorsements : NULL,
            (const uint8_t*)&hash,
            sizeof(hash));

        OE_TEST_CODE(oe_free_claims(claims, claims_size), OE_OK);
        claims = NULL;
        claims_size = 0;

        result = oe_verify_evidence(
            &_ecdsa_quote_uuid,
            (const uint8_t*)quote,
            quote_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_size);
        OE_TEST(result == OE_OK || result == OE_TCB_LEVEL_INVALID);
        tcb_level_valid = (result == OE_OK);

        _test_claims(
            claims,
            claims_size,
            SGX_FORMAT_TYPE_RAW_QUOTE,
            is_local,
            tcb_level_valid,
            report_body,
            &_ecdsa_quote_uuid,
            expected_endorsements ? &sgx_endorsements : NULL,
            (const uint8_t*)&hash,
            sizeof(hash));

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
