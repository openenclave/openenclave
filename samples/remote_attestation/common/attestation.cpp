// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <string.h>
#include "log.h"

// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

Attestation::Attestation(Crypto* crypto, uint8_t* enclave_mrsigner)
{
    m_crypto = crypto;
    m_enclave_mrsigner = enclave_mrsigner;
}

/**
 * Generate remote evidence for the given data.
 */
bool Attestation::generate_remote_evidence(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** remote_evidence_buf,
    size_t* remote_evidence_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    oe_result_t attester_result = OE_OK;

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    // Initialize attester and use the SGX plugin.
    attester_result = oe_attester_initialize();
    if (attester_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_initialize failed.");
        goto exit;
    }

    // Generate evidence based on the format selected by the attester.
    result = oe_get_evidence(
        &sgx_remote_uuid,
        NULL,
        NULL,
        0,
        NULL,
        0,
        remote_evidence_buf,
        remote_evidence_buf_size,
        NULL,
        0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.");
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("generate_remote_evidence succeeded.");
exit:
    return ret;
}

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the value stored with that
 * claim name in the list.
 */
static const oe_claim_t* _find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return NULL;
}

/**
 * Attest the given remote evidence and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The remote evidence is first attested using the oe_verify_evidence API.
 * This ensures the authenticity of the enclave that generated the remote
 * evidence. 2) Next, to establish trust of the enclave that  generated the
 * remote evidence, the mrsigner, product_id, isvsvn values are checked to  see
 * if they are predefined trusted values.
 */
bool Attestation::attest_remote_evidence(
    const uint8_t* remote_evidence,
    size_t remote_evidence_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    oe_result_t verifier_result = OE_OK;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;
    const oe_claim_t* claim;

    // While attesting, the remote evidence being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(remote_evidence, remote_evidence_size))
    {
        TRACE_ENCLAVE("Cannot attest remote evidence in host memory. Unsafe.");
        goto exit;
    }

    // Initialize the verifier.
    verifier_result = oe_verifier_initialize();
    if (verifier_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }

    // Validate the evidence's trustworthiness
    // Verify the remote evidence to ensure its authenticity.
    result = oe_verify_evidence(
        &sgx_remote_uuid,
        remote_evidence,
        remote_evidence_size,
        NULL,
        0,
        NULL,
        0,
        &claims,
        &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE(
            "oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    // 1) Validate the signer id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        NULL)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    };

    if (memcmp(claim->value, m_enclave_mrsigner, 32) != 0)
    {
        TRACE_ENCLAVE("signer_id checking failed.");
        TRACE_ENCLAVE("signer_id %s", claim->value);

        for (int j = 0; j < 32; j++)
        {
            TRACE_ENCLAVE(
                "m_enclave_mrsigner[%d]=0x%0x\n",
                j,
                (uint8_t)m_enclave_mrsigner[j]);
        }

        TRACE_ENCLAVE("\n\n\n");

        for (int j = 0; j < 32; j++)
        {
            TRACE_ENCLAVE(
                "signer_id)[%d]=0x%0x\n", j, (uint8_t)claim->value[j]);
        }
        TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
        goto exit;
    }

    // 2) Check the enclave's product id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        NULL)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    };

    if (claim->value[0] != 1)
    {
        TRACE_ENCLAVE("product_id checking failed.");
        goto exit;
    }

    // 3) Check the enclave's security version.
    if ((claim = _find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == NULL)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    };

    if (claim->value[0] < 1)
    {
        TRACE_ENCLAVE("security_version checking failed.");
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("remote attestation succeeded.");
exit:
    return ret;
}
