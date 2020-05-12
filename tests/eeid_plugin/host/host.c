// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

#include <openenclave/attestation/plugin.h>
#include <openenclave/attestation/sgx/eeid_verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>

#if defined(_WIN32)
#include <ShlObj.h>
#include <Windows.h>
#endif

#include "../../../host/sgx/quote.h"
#include "../test_helpers.h"
#include "eeid_plugin_u.h"

#define SKIP_RETURN_CODE 2

void host_verify(
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsements,
    size_t endorsements_size)
{
    printf("====== running host_verify.\n");

    oe_claim_t* claims = NULL;
    size_t claims_size = 0;
    OE_TEST(
        oe_verify_evidence(
            evidence, evidence_size, NULL, 0, NULL, 0, &claims, &claims_size) ==
        OE_OK);

    oe_free_claims_list(claims, claims_size);

    claims = NULL;
    claims_size = 0;

    // Test with endorsements currently fails.
    OE_UNUSED(endorsements);
    OE_UNUSED(endorsements_size);
    // OE_TEST(
    //     oe_verify_evidence(
    //         evidence,
    //         evidence_size,
    //         endorsements,
    //         endorsements_size,
    //         NULL,
    //         0,
    //         &claims,
    //         &claims_size) == OE_OK);
}

int main(int argc, const char* argv[])
{
#ifdef OE_LINK_SGX_DCAP_QL
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

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

    oe_verifier_t* verifier = oe_eeid_plugin_verifier();
    oe_register_verifier(verifier, NULL, 0);

    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    setting.u.eeid = mk_test_eeid();

    result = oe_create_eeid_plugin_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, &setting, 1, &enclave);
    OE_TEST(result == OE_OK);

    run_tests(enclave);

    oe_unregister_verifier(verifier);
    free(setting.u.eeid);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
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
