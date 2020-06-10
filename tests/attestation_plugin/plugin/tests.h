// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ATTESTATION_PLUGIN_TESTS
#define _OE_ATTESTATION_PLUGIN_TESTS

#include <openenclave/internal/plugin.h>

#define CLAIM1_NAME "Hello"
#define CLAIM1_VALUE "World!"
#define CLAIM2_NAME "123"
#define CLAIM2_VALUE "456"

#define NUM_TEST_CLAIMS 2
extern oe_claim_t test_claims[2];

void test_runtime();

void register_verifier();

void unregister_verifier();

void verify_sgx_evidence(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    const oe_claim_t* custom_claims,
    size_t custom_claims_size,
    bool is_local);

#endif // _OE_ATTESTATION_PLUGIN_TESTS