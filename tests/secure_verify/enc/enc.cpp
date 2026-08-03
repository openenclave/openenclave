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

static const oe_uuid_t _tdx_quote_uuid = {OE_FORMAT_UUID_TDX_QUOTE_ECDSA};

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

static const oe_claim_t* _find_claim(
    const oe_claim_t* claims,
    size_t claims_length,
    const char* name)
{
    for (size_t i = 0; i < claims_length; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &claims[i];
    }

    return NULL;
}

oe_result_t verify_plugin_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size,
    uint8_t* endorsement,
    size_t endorsement_size,
    int64_t tcb_baseline_date,
    uint8_t has_tcb_baseline_date)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    oe_policy_t policies[1];
    oe_policy_t* policies_ptr = NULL;
    size_t policies_size = 0;

    if (has_tcb_baseline_date)
    {
        policies[0].type = OE_POLICY_TCB_BASELINE_DATE;
        policies[0].policy = &tcb_baseline_date;
        policies[0].policy_size = sizeof(tcb_baseline_date);
        policies_ptr = policies;
        policies_size = 1;
        printf(
            "Applying TCB baseline date policy: %lld (epoch seconds)\n",
            (long long)tcb_baseline_date);
    }

    OE_CHECK(oe_verifier_initialize());
    OE_CHECK(oe_tdx_verifier_initialize());

    OE_CHECK_MSG(
        oe_verify_evidence(
            format_id,
            evidence,
            evidence_size,
            endorsement,
            endorsement_size,
            policies_ptr,
            policies_size,
            &claims,
            &claims_length),
        "Failed to verify evidence. result=%u (%s)\n",
        result,
        oe_result_str(result));

    _dump_claims(claims, claims_length);

    if (memcmp(format_id, &_tdx_quote_uuid, sizeof(*format_id)) == 0)
    {
        const oe_claim_t* tcb_date =
            _find_claim(claims, claims_length, OE_CLAIM_TCB_DATE);
        const oe_claim_t* baseline = _find_claim(
            claims, claims_length, OE_CLAIM_TCB_BASELINE_DATE);

        if (!tcb_date || tcb_date->value_size != sizeof(oe_datetime_t))
            OE_RAISE_MSG(
                OE_VERIFY_FAILED, "Missing or invalid TCB date claim");

        if (has_tcb_baseline_date)
        {
            if (!baseline ||
                baseline->value_size != sizeof(tcb_baseline_date) ||
                memcmp(
                    baseline->value,
                    &tcb_baseline_date,
                    sizeof(tcb_baseline_date)) != 0)
                OE_RAISE_MSG(
                    OE_VERIFY_FAILED, "Missing or invalid TCB baseline claim");
        }
        else if (baseline)
        {
            OE_RAISE_MSG(
                OE_VERIFY_FAILED,
                "Unexpected TCB baseline claim without baseline policy");
        }
    }

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
