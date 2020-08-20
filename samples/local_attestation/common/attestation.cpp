// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/report.h>
#include <string.h>
#include "log.h"

// SGX local attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

Attestation::Attestation(Crypto* crypto, uint8_t* enclave_signer_id)
{
    m_crypto = crypto;
    m_enclave_signer_id = enclave_signer_id;
}

/**
 * Get format settings for the given enclave.
 */
bool Attestation::get_format_settings(
    uint8_t** format_settings,
    size_t* format_settings_size)
{
    bool ret = false;

    // Intialize verifier to get enclave's format settings.
    if (oe_verifier_initialize() != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed");
        goto exit;
    }

    // Use the SGX plugin.
    if (oe_verifier_get_format_settings(
            &sgx_local_uuid, format_settings, format_settings_size) != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_get_format_settings failed");
        goto exit;
    }
    ret = true;
exit:
    return ret;
}

/**
 * Generate evidence for the given data.
 */
bool Attestation::generate_local_attestation_evidence(
    uint8_t* format_settings,
    size_t format_settings_size,
    const uint8_t* data,
    const size_t data_size,
    uint8_t** evidence,
    size_t* evidence_size)
{
    bool ret = false;
    uint8_t hash[32];
    oe_result_t result = OE_OK;
    uint8_t* custom_claims_buffer = nullptr;
    size_t custom_claims_buffer_size = 0;
    char custom_claim1_name[] = "Event";
    char custom_claim1_value[] = "Local attestation sample";
    char custom_claim2_name[] = "Public key hash";

    // The custom_claims[1].value will be filled with hash of public key later
    oe_claim_t custom_claims[2] = {
        {.name = custom_claim1_name,
         .value = (uint8_t*)custom_claim1_value,
         .value_size = sizeof(custom_claim1_value)},
        {.name = custom_claim2_name, .value = nullptr, .value_size = 0}};

    if (m_crypto->Sha256(data, data_size, hash) != 0)
    {
        TRACE_ENCLAVE("data hashing failed");
        goto exit;
    }

    // Initialize attester and use the SGX plugin.
    result = oe_attester_initialize();
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_attester_initialize failed.");
        goto exit;
    }

    // serialize the custom claims, store hash of data in custom_claims[1].value
    custom_claims[1].value = hash;
    custom_claims[1].value_size = sizeof(hash);

    TRACE_ENCLAVE("oe_serialize_custom_claims");
    if (oe_serialize_custom_claims(
            custom_claims,
            2,
            &custom_claims_buffer,
            &custom_claims_buffer_size) != OE_OK)
    {
        TRACE_ENCLAVE("oe_serialize_custom_claims failed.");
        goto exit;
    }
    TRACE_ENCLAVE(
        "serialized custom claims buffer size: %lu", custom_claims_buffer_size);

    // Generate evidence based on the format selected by the attester.
    result = oe_get_evidence(
        &sgx_local_uuid,
        0,
        custom_claims_buffer,
        custom_claims_buffer_size,
        format_settings,
        format_settings_size,
        evidence,
        evidence_size,
        nullptr,
        0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_evidence failed.(%s)", oe_result_str(result));
        goto exit;
    }
    ret = true;
    TRACE_ENCLAVE("generate_local_attestation_evidence succeeded");
exit:
    return ret;
}

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
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
    return nullptr;
}

/**
 * Attest the given evidence and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The local evidence is first attested using the oe_verify_evidence API.
 * This ensures the authenticity of the enclave that generated the evidence. 2)
 * Next, to establish trust of the enclave that generated the evidence, the
 * signer_id, product_id, the security version values are checked to see if they
 * are predefined trusted values.
 */
bool Attestation::attest_local_attestation_evidence(
    const uint8_t* evidence,
    size_t evidence_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t hash[32];
    oe_result_t result = OE_OK;
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;
    const oe_claim_t* claim;
    oe_claim_t* custom_claims = nullptr;
    size_t custom_claims_length = 0;

    // While attesting, the evidence being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(evidence, evidence_size))
    {
        TRACE_ENCLAVE("cannot attest evidence in host memory. unsafe");
        goto exit;
    }

    // 1)  Validate the evidence's trustworthiness
    // Verify the evidence to ensure its authenticity.
    // We do not need to initialize the verifier as the verifier, using the SGX
    // plugin, has been initialized when getting the enclave's format settings
    result = oe_verify_evidence(
        &sgx_local_uuid,
        evidence,
        evidence_size,
        nullptr,
        0,
        nullptr,
        0,
        &claims,
        &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_evidence failed (%s)", oe_result_str(result));
        goto exit;
    }

    TRACE_ENCLAVE("oe_verify_evidence succeeded");

    // 2) validate the enclave identity's signed_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.

    // Validate the signer id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        nullptr)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    };

    if (claim->value_size != OE_SIGNER_ID_SIZE)
    {
        TRACE_ENCLAVE("signer_id size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    if (memcmp(claim->value, m_enclave_signer_id, OE_SIGNER_ID_SIZE) != 0)
    {
        TRACE_ENCLAVE("signer_id checking failed");

        for (int j = 0; j < OE_SIGNER_ID_SIZE; j++)
        {
            TRACE_ENCLAVE(
                "m_enclave_signer_id[%d]=0x%0x",
                j,
                (uint8_t)m_enclave_signer_id[j]);
        }

        TRACE_ENCLAVE("\n");

        for (int j = 0; j < OE_SIGNER_ID_SIZE; j++)
        {
            TRACE_ENCLAVE("signer_id[%d]=0x%0x", j, (uint8_t)claim->value[j]);
        }
        goto exit;
    }

    // Check the enclave's product id.
    if ((claim = _find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr)
    {
        TRACE_ENCLAVE("could not find claim");
        goto exit;
    };

    if (claim->value_size != OE_PRODUCT_ID_SIZE)
    {
        TRACE_ENCLAVE(
            "product_id size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    if (*(claim->value) != 1)
    {
        TRACE_ENCLAVE("product_id(%u) checking failed", *(claim->value));
        goto exit;
    }

    // Check the enclave's security version.
    if ((claim = _find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == nullptr)
    {
        TRACE_ENCLAVE("could not find claim");
        goto exit;
    };

    if (claim->value_size != sizeof(uint32_t))
    {
        TRACE_ENCLAVE(
            "security_version size(%lu) checking failed", claim->value_size);
        goto exit;
    }

    if (*(claim->value) < 1)
    {
        TRACE_ENCLAVE("security_version(%u) checking failed", *(claim->value));
        goto exit;
    }

    // 3) Validate the custom claims buffer
    //    Deserialize the custom claims buffer to custom claims list, then fetch
    //    the hash value of the data held in custom_claims[1]
    if ((claim = _find_claim(
             claims, claims_length, OE_CLAIM_CUSTOM_CLAIMS_BUFFER)) == nullptr)
    {
        TRACE_ENCLAVE("Could not find claim.");
        goto exit;
    }

    if (m_crypto->Sha256(data, data_size, hash) != 0)
    {
        goto exit;
    }

    // deserialize the custom claims buffer
    TRACE_ENCLAVE("oe_deserialize_custom_claims");
    if (oe_deserialize_custom_claims(
            claim->value,
            claim->value_size,
            &custom_claims,
            &custom_claims_length) != OE_OK)
    {
        TRACE_ENCLAVE("oe_deserialize_custom_claims failed.");
        goto exit;
    }

    TRACE_ENCLAVE(
        "custom claim 1(%s): %s",
        custom_claims[0].name,
        custom_claims[0].value);

    TRACE_ENCLAVE("custom claim 2(%s) hash check:", custom_claims[1].name);

    if (custom_claims[1].value_size != sizeof(hash) ||
        memcmp(custom_claims[1].value, hash, sizeof(hash)) != 0)
    {
        TRACE_ENCLAVE("hash mismatch");
        goto exit;
    }
    TRACE_ENCLAVE("hash match");

    ret = true;
    TRACE_ENCLAVE("attest_local_attestation_evidence succeeded");
exit:
    // Shut down attester/verifier and free claims.
    oe_attester_shutdown();
    oe_verifier_shutdown();
    oe_free_claims(claims, claims_length);
    return ret;
}
