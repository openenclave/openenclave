// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ATTESTATION_PLUGIN_TESTS
#define _OE_ATTESTATION_PLUGIN_TESTS

#include <openenclave/internal/plugin.h>

#define TEST_CLAIMS_SIZE 64
extern uint8_t test_claims[TEST_CLAIMS_SIZE];

void test_runtime();

void register_verifier();

void unregister_verifier();

void verify_sgx_evidence(
    const oe_uuid_t* format_id,
    bool wrapped_with_header,
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    const uint8_t* custom_claims,
    size_t custom_claims_size);

#endif // _OE_ATTESTATION_PLUGIN_TESTS