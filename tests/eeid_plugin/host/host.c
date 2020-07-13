// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/plugin.h>
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

    claims = NULL;
    claims_length = 0;

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
}

void host_remote_verify(oe_enclave_t* enclave)
{
    printf("====== running host_remote_verify.\n");

    oe_result_t result;

    size_t evidence_size = 65536, evidence_out_size = 0;
    uint8_t evidence[evidence_size];
    size_t endorsements_size = 65536, endorsements_out_size = 0;
    uint8_t endorsements[endorsements_size];
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_TEST_CODE(
        get_eeid_evidence(
            enclave,
            &result,
            evidence,
            evidence_size,
            &evidence_out_size,
            endorsements,
            endorsements_size,
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
}

void one_enclave_tests(const char* filename, uint32_t flags)
{
    printf("====== running one_enclave_tests.\n");

    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    make_test_eeid(&setting.u.eeid, 10 * OE_PAGE_SIZE);

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_eeid_plugin_enclave(
        filename, OE_ENCLAVE_TYPE_AUTO, flags, &setting, 1, &enclave);
    OE_TEST(result == OE_OK);

    run_tests(enclave);
    host_remote_verify(enclave);
    free(setting.u.eeid);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
}

typedef struct
{
    const char* filename;
    oe_enclave_t* enclave;
    oe_eeid_t* eeid;

    size_t evidence_size;
    size_t evidence_out_size;
    uint8_t* evidence;
    size_t endorsements_size;
    size_t endorsements_out_size;
    uint8_t* endorsements;
    oe_claim_t* claims;
    size_t claims_length;
    const uint8_t* enclave_hash;
    const uint8_t* base_enclave_hash;
} enclave_stuff_t;

void free_stuff(enclave_stuff_t* stuff)
{
    free(stuff->eeid);
    free(stuff->evidence);
    free(stuff->endorsements);
}

void start_enclave(const char* filename, uint32_t flags, enclave_stuff_t* stuff)
{
    oe_result_t result = OE_UNEXPECTED;
    stuff->filename = filename;
    stuff->enclave = NULL;
    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    setting.u.eeid = stuff->eeid;

    OE_TEST_CODE(
        oe_create_eeid_plugin_enclave(
            stuff->filename,
            OE_ENCLAVE_TYPE_AUTO,
            flags,
            &setting,
            1,
            &stuff->enclave),
        OE_OK);

    stuff->evidence_size = 65536;
    stuff->evidence = malloc(stuff->evidence_size);
    stuff->endorsements_size = 65536;
    stuff->endorsements = malloc(stuff->endorsements_size);
    stuff->claims = NULL;
    stuff->claims_length = 0;

    OE_TEST_CODE(
        get_eeid_evidence(
            stuff->enclave,
            &result,
            stuff->evidence,
            stuff->evidence_size,
            &stuff->evidence_out_size,
            stuff->endorsements,
            stuff->endorsements_size,
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
        if (strcmp(stuff->claims[i].name, OE_CLAIM_UNIQUE_ID) == 0)
            stuff->enclave_hash = stuff->claims[i].value;
        else if (strcmp(stuff->claims[i].name, OE_CLAIM_EEID_BASE_ID) == 0)
            stuff->base_enclave_hash = stuff->claims[i].value;

    OE_TEST(stuff->enclave_hash != NULL);
}

void multiple_enclaves_tests(const char* filename, uint32_t flags)
{
    printf("====== running multiple_enclaves_tests.\n");

    // Enclave A
    enclave_stuff_t A;
    OE_TEST(make_test_eeid(&A.eeid, 10) == OE_OK);
    start_enclave(filename, flags, &A);

    // Enclave B with reversed EEID
    enclave_stuff_t B;
    OE_TEST(make_test_eeid(&B.eeid, 10) == OE_OK);
    for (size_t i = 0; i < B.eeid->data_size; i++)
        B.eeid->data[i] = (uint8_t)(9 - i);
    start_enclave(filename, flags, &B);

    // Check that the hashes of A and B are not the same
    OE_TEST(memcmp(A.enclave_hash, B.enclave_hash, OE_SHA256_SIZE) != 0);

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
    OE_TEST(make_test_eeid(&C.eeid, 10) == OE_OK);
    start_enclave(filename, flags, &C);

    // Check that the hashes of A and C are indeed the same
    OE_TEST(memcmp(A.enclave_hash, C.enclave_hash, OE_SHA256_SIZE) == 0);

    OE_TEST(oe_terminate_enclave(C.enclave) == OE_OK);

    // The base images of all three are the same
    OE_TEST(
        memcmp(A.base_enclave_hash, B.base_enclave_hash, OE_SHA256_SIZE) == 0);
    OE_TEST(
        memcmp(B.base_enclave_hash, C.base_enclave_hash, OE_SHA256_SIZE) == 0);

    free_stuff(&A);
    free_stuff(&B);
    free_stuff(&C);
}

int main(int argc, const char* argv[])
{
#ifdef OE_LINK_SGX_DCAP_QL
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    // Skip test in simulation mode because of memory alignment issues, same as
    // tests/attestation_plugin).
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    OE_TEST_CODE(oe_sgx_eeid_verifier_initialize(), OE_OK);

    one_enclave_tests(argv[1], flags);
    multiple_enclaves_tests(argv[1], flags);

    oe_sgx_eeid_verifier_shutdown();

    return 0;
#else
    // This test should not run on any platforms where HAS_QUOTE_PROVIDER is not
    // defined.
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    printf("=== tests skipped when built with HAS_QUOTE_PROVIDER=OFF\n");
    return SKIP_RETURN_CODE;
#endif
}
