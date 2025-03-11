// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
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

static void _dump_hex(char* key, uint8_t* data, size_t size)
{
    printf("%s: ", key);
    for (size_t i = 0; i < size; i++)
        printf("%02x", data[i]);
    printf("\n");
}

static void _dump_str(char* key, char* data, size_t size)
{
    if (size)
        printf("%s (%zu): %s\n", key, size, data);
    else
        printf("%s (%zu):\n", key, size);
}

static void _dump_claims(oe_claim_t* claims, size_t claims_length)
{
    for (size_t i = 0; i < claims_length; i++)
    {
        if (strcmp(claims[i].name, OE_CLAIM_TDX_SA_LIST) != 0)
            _dump_hex(claims[i].name, claims[i].value, claims[i].value_size);
        else
            _dump_str(
                claims[i].name, (char*)claims[i].value, claims[i].value_size);
    }
}

oe_result_t verify_plugin_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsement,
    size_t endorsement_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    OE_CHECK(oe_verifier_initialize());
    OE_CHECK(oe_tdx_verifier_initialize());

    OE_CHECK_MSG(
        oe_verify_evidence(
            format_id,
            evidence,
            evidence_size,
            endorsement,
            endorsement_size,
            NULL,
            0,
            &claims,
            &claims_length),
        "Failed to verify evidence. result=%u (%s)\n",
        result,
        oe_result_str(result));

    _dump_claims(claims, claims_length);

    result = OE_OK;

done:
    OE_CHECK(oe_free_claims(claims, claims_length));
    OE_CHECK(oe_verifier_shutdown());
    OE_CHECK(oe_tdx_verifier_shutdown());

    return result;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
