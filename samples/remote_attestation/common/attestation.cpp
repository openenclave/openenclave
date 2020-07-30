// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

Attestation::Attestation(Crypto* crypto, uint8_t* enclave_mrsigner)
{
    m_crypto = crypto;
    m_enclave_mrsigner = enclave_mrsigner;
}

/**
 * Generate a remote report for the given data. The SHA256 digest of the data is
 * stored in the report_data field of the generated remote report.
 */
bool Attestation::generate_remote_report(
    const uint8_t* data,
    const size_t data_size,
    uint8_t** remote_report_buf,
    size_t* remote_report_buf_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_result_t result = OE_OK;
    oe_result_t attester_result = OE_OK;
    // uint8_t* temp_buf = NULL;

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
    result = oe_get_evidence(&sgx_remote_uuid, NULL, NULL, 0, NULL, 0, remote_report_buf, remote_report_buf_size, NULL, 0);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_report failed.");
        goto exit;
    }
    //*remote_report_buf = temp_buf;
    ret = true;
    TRACE_ENCLAVE("generate_remote_report succeeded.");
exit:
    return ret;
}

/**
 * Attest the given remote report and accompanying data. It consists of the
 * following three steps:
 *
 * 1) The remote report is first attested using the oe_verify_report API. This
 * ensures the authenticity of the enclave that generated the remote report.
 * 2) Next, to establish trust of the enclave that  generated the remote report,
 * the mrsigner, product_id, isvsvn values are checked to  see if they are
 * predefined trusted values.
 * 3) Once the enclave's trust has been established, the validity of
 * accompanying data is ensured by comparing its SHA256 digest against the
 * report_data field.
 */
bool Attestation::attest_remote_report(
    const uint8_t* remote_report,
    size_t remote_report_size,
    const uint8_t* data,
    size_t data_size)
{
    bool ret = false;
    uint8_t sha256[32];
    oe_report_t parsed_report = {0};
    oe_result_t result = OE_OK;
    oe_result_t verifier_result = OE_OK;
    oe_claim_t* claims = NULL;
    size_t claims_length = 0;

    // While attesting, the remote report being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(remote_report, remote_report_size))
    {
        TRACE_ENCLAVE("Cannot attest remote report in host memory. Unsafe.");
        goto exit;
    }

    // Initialize the verifier.
    verifier_result = oe_verifier_initialize();
    if (verifier_result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verifier_initialize failed.");
        goto exit;
    }

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    result =
        oe_verify_evidence(&sgx_remote_uuid, remote_report, remote_report_size, NULL, 0, NULL, 0, &claims, &claims_length);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_evidence failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    // Iterate through list of claims.
    for (size_t i = 0; i < claims_length; i++) 
    {
        if (strcmp(claims[i].name, OE_CLAIM_SIGNER_ID) == 0)
        {
            // Validate the signer id.
            if (memcmp(claims[i].value, m_enclave_mrsigner, 32) != 0)
            {
                TRACE_ENCLAVE("signer_id checking failed.");
                TRACE_ENCLAVE(
                    "signer_id %s", claims[i].value);

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
                        "signer_id)[%d]=0x%0x\n",
                        j,
                        (uint8_t)claims[i].value[j]);
                }
                TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
                goto exit;
            }
        }
        if (strcmp(claims[i].name, OE_CLAIM_PRODUCT_ID) == 0)
        {
            // Check the enclave's product id.
            if (claims[i].value[0] != 1)
            {
                TRACE_ENCLAVE("product_id checking failed.");
                goto exit;
            }
        }
        if (strcmp(claims[i].name, OE_CLAIM_SECURITY_VERSION) == 0)
        {
            // Check the enclave's security version.
            if (claims[1].value[0] < 1)
            {
                TRACE_ENCLAVE("security_version checking failed.");
                goto exit;
            }
        }
    }

    ret = true;
    TRACE_ENCLAVE("remote attestation succeeded.");
exit:
    return ret;
}
