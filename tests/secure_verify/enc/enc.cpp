// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secure_verify_t.h"

oe_result_t verify_plugin_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_CHECK(oe_verifier_initialize());

    OE_CHECK_MSG(
        oe_verify_evidence(
            format_id,
            evidence,
            evidence_size,
            nullptr,
            0,
            NULL,
            0,
            &claims,
            &claims_length),
        "Failed to verify evidence. result=%u (%s)\n",
        result,
        oe_result_str(result));

    result = OE_OK;

done:
    OE_CHECK(oe_free_claims(claims, claims_length));
    OE_CHECK(oe_verifier_shutdown());

    return result;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
