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
#include "attestation_perf_t.h"

oe_result_t get_evidence(
    uint8_t* evidence_out,
    size_t evidence_size,
    size_t* evidence_out_size,
    bool verify)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* local_evidence = NULL;
    size_t local_evidence_size = 0;

    {
        static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
        OE_CHECK(oe_attester_initialize());
        OE_CHECK(oe_get_evidence(
            &_ecdsa_uuid,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &local_evidence,
            &local_evidence_size,
            NULL,
            0));
        OE_CHECK(oe_attester_shutdown());

        if (evidence_out) // Caller wants to get evidence buffer
        {
            if (local_evidence_size > evidence_size)
                return OE_BUFFER_TOO_SMALL;

            oe_memcpy_s(
                evidence_out,
                evidence_size,
                local_evidence,
                local_evidence_size);
            *evidence_out_size = local_evidence_size;
        }
        else if (evidence_out_size)
        {
            *evidence_out_size = 0;
        }
    }

    if (verify)
    {
        oe_claim_t* claims = NULL;
        size_t claims_length = 0;

        OE_CHECK(oe_verifier_initialize());
        OE_CHECK(oe_verify_evidence(
            NULL,
            local_evidence,
            local_evidence_size,
            NULL,
            0,
            NULL,
            0,
            &claims,
            &claims_length));
        oe_free_claims(claims, claims_length);
        OE_CHECK(oe_verifier_shutdown());
    }

    result = OE_OK;

done:
    oe_free_evidence(local_evidence);

    return result;
}
