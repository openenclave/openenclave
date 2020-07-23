// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/plugin.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>

#include "../../../common/sgx/endorsements.h"
#include "../../../host/sgx/quote.h"
#include "../test_helpers.h"
#include "eeid_plugin_u.h"

#define SKIP_RETURN_CODE 2

void host_ocall_verify(
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsements,
    size_t endorsements_size)
{
    printf("====== running host_ocall_verify.\n");

    // Without endorsements
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;
    OE_TEST_CODE(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_OK);

    oe_free_claims(claims, claims_length);

    // With endorsements
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

    oe_free_claims(claims, claims_length);
}

void host_remote_verify(oe_enclave_t* enclave)
{
    printf("====== running host_remote_verify.\n");

    oe_result_t result;

    uint8_t evidence[65535];
    uint8_t endorsements[65535];
    size_t evidence_out_size = 0, endorsements_out_size = 0;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_TEST_CODE(
        get_eeid_evidence(
            enclave,
            &result,
            evidence,
            sizeof(evidence),
            &evidence_out_size,
            endorsements,
            sizeof(endorsements),
            &endorsements_out_size),
        OE_OK);

    // Without endorsements
    OE_TEST_CODE(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_out_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_OK);

    oe_free_claims(claims, claims_length);

    // With endorsements
    OE_TEST_CODE(
        oe_verify_evidence(
            NULL,
            evidence,
            evidence_out_size,
            endorsements,
            endorsements_out_size,
            NULL,
            0,
            &claims,
            &claims_length),
        OE_OK);

    oe_free_claims(claims, claims_length);
}

void one_enclave_tests(const char* filename, uint32_t flags, bool static_sizes)
{
    printf("======== one_enclave_tests.\n");

    oe_enclave_setting_eeid_t* eeid_setting = NULL;
    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    make_test_eeid(&eeid_setting, 10 * OE_PAGE_SIZE, static_sizes);
    setting.u.eeid_setting = eeid_setting;

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_eeid_plugin_enclave(
        filename, OE_ENCLAVE_TYPE_AUTO, flags, &setting, 1, &enclave);
    OE_TEST(result == OE_OK);

    run_tests(enclave);
    host_remote_verify(enclave);
    free((void*)setting.u.eeid_setting);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
}

typedef struct
{
    const char* filename;
    oe_enclave_t* enclave;
    oe_enclave_setting_eeid_t* eeid_setting;

    uint8_t evidence[65535];
    size_t evidence_out_size;
    uint8_t endorsements[65535];
    size_t endorsements_out_size;
    oe_claim_t* claims;
    size_t claims_length;
    const uint8_t* enclave_hash;
    const uint8_t* resigned_enclave_hash;
    const uint8_t* config_hash;
} enclave_stuff_t;

void free_stuff(enclave_stuff_t* stuff)
{
    free(stuff->eeid_setting);
    oe_free_claims(stuff->claims, stuff->claims_length);
}

void start_enclave(const char* filename, uint32_t flags, enclave_stuff_t* stuff)
{
    oe_result_t result = OE_UNEXPECTED;
    stuff->filename = filename;
    stuff->enclave = NULL;
    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    setting.u.eeid_setting = stuff->eeid_setting;

    OE_TEST_CODE(
        oe_create_eeid_plugin_enclave(
            stuff->filename,
            OE_ENCLAVE_TYPE_AUTO,
            flags,
            &setting,
            1,
            &stuff->enclave),
        OE_OK);

    stuff->claims = NULL;
    stuff->claims_length = 0;

    OE_TEST_CODE(
        get_eeid_evidence(
            stuff->enclave,
            &result,
            stuff->evidence,
            sizeof(stuff->evidence),
            &stuff->evidence_out_size,
            stuff->endorsements,
            sizeof(stuff->endorsements),
            &stuff->endorsements_out_size),
        OE_OK);
    OE_TEST(result == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            NULL,
            stuff->evidence,
            stuff->evidence_out_size,
            NULL,
            0,
            NULL,
            0,
            &stuff->claims,
            &stuff->claims_length) == OE_OK);

    OE_TEST(
        oe_verify_evidence(
            NULL,
            stuff->evidence,
            stuff->evidence_out_size,
            stuff->endorsements,
            stuff->endorsements_out_size,
            NULL,
            0,
            &stuff->claims,
            &stuff->claims_length) == OE_OK);

    stuff->enclave_hash = NULL;
    for (size_t i = 0; i < stuff->claims_length; i++)
    {
        const char* name = stuff->claims[i].name;
        if (strcmp(name, OE_CLAIM_UNIQUE_ID) == 0)
            stuff->enclave_hash = stuff->claims[i].value;
        else if (strcmp(name, OE_CLAIM_EEID_RESIGNED_UNIQUE_ID) == 0)
            stuff->resigned_enclave_hash = stuff->claims[i].value;
        else if (strcmp(name, OE_CLAIM_CONFIG_ID) == 0)
            stuff->config_hash = stuff->claims[i].value;
    }

    OE_TEST(stuff->enclave_hash != NULL);

    /* Check that the claimed config_id matches */
    OE_SHA256 config_hash;
    oe_sha256(
        stuff->eeid_setting->data,
        stuff->eeid_setting->data_size,
        &config_hash);
    OE_TEST(memcmp(config_hash.buf, stuff->config_hash, OE_SHA256_SIZE) == 0);
}

void multiple_enclaves_tests(
    const char* filename,
    uint32_t flags,
    bool static_sizes)
{
    printf("======== multiple_enclaves_tests.\n");

    // Enclave A
    enclave_stuff_t A;
    OE_TEST(make_test_eeid(&A.eeid_setting, 10, static_sizes) == OE_OK);
    start_enclave(filename, flags, &A);

    // Enclave B with reversed EEID
    enclave_stuff_t B;
    OE_TEST(make_test_eeid(&B.eeid_setting, 10, static_sizes) == OE_OK);
    for (size_t i = 0; i < B.eeid_setting->data_size; i++)
        B.eeid_setting->data[i] = (uint8_t)(9 - i);
    start_enclave(filename, flags, &B);

    // Check that the hashes of A and B are not the same
    OE_TEST(
        memcmp(
            A.resigned_enclave_hash, B.resigned_enclave_hash, OE_SHA256_SIZE) !=
        0);

    // Faulty endorsements must fail
    OE_TEST(
        oe_verify_evidence(
            NULL,
            A.evidence,
            A.evidence_out_size,
            B.endorsements,
            B.endorsements_out_size,
            NULL,
            0,
            &A.claims,
            &A.claims_length) == OE_VERIFY_FAILED);

    OE_TEST(oe_terminate_enclave(A.enclave) == OE_OK);
    OE_TEST(oe_terminate_enclave(B.enclave) == OE_OK);

    // Enclave C with same EEID as A
    enclave_stuff_t C;
    OE_TEST(make_test_eeid(&C.eeid_setting, 10, static_sizes) == OE_OK);
    start_enclave(filename, flags, &C);

    // Check that the hashes of A and C are indeed the same
    OE_TEST(
        memcmp(
            A.resigned_enclave_hash, C.resigned_enclave_hash, OE_SHA256_SIZE) ==
        0);

    OE_TEST(oe_terminate_enclave(C.enclave) == OE_OK);

    // The base images of all three are the same
    OE_TEST(memcmp(A.enclave_hash, B.enclave_hash, OE_SHA256_SIZE) == 0);
    OE_TEST(memcmp(B.enclave_hash, C.enclave_hash, OE_SHA256_SIZE) == 0);

    free_stuff(&A);
    free_stuff(&B);
    free_stuff(&C);
}

int main(int argc, const char* argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE dynamic/static\n", argv[0]);
        exit(1);
    }

    if (!oe_has_sgx_quote_provider())
    {
        // this test should not run on any platforms where DCAP libraries are
        // not found.
        OE_TRACE_INFO("=== tests skipped when DCAP libraries are not found.\n");
        return SKIP_RETURN_CODE;
    }

    // Skip test in simulation mode because of memory alignment issues, same as
    // tests/attestation_plugin).
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    OE_TEST_CODE(oe_sgx_eeid_verifier_initialize(), OE_OK);

    bool static_sizes = strcmp(argv[2], "static") == 0;
    one_enclave_tests(argv[1], flags, static_sizes);
    multiple_enclaves_tests(argv[1], flags, static_sizes);

    oe_sgx_eeid_verifier_shutdown();

    return 0;
}
