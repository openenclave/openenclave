// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_EEID_PLUGIN_TEST_HELPERS_
#define _OE_EEID_PLUGIN_TEST_HELPERS_

#include <openenclave/bits/eeid.h>

oe_eeid_t* mk_test_eeid();

void verify_sgx_evidence(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* endorsements,
    size_t endorsements_size,
    const oe_claim_t* custom_claims,
    size_t custom_claims_size,
    bool is_local);

#endif // _OE_EEID_PLUGIN_TEST_HELPERS_S