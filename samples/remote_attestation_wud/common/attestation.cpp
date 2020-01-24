// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <string.h>
#include "log.h"

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
    uint8_t* temp_buf = NULL;

    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    // To generate a remote report that can be attested remotely by an enclave
    // running  on a different platform, pass the
    // OE_REPORT_FLAGS_REMOTE_ATTESTATION option. This uses the trusted
    // quoting enclave to generate the report based on this enclave's local
    // report.
    // To generate a remote report that just needs to be attested by another
    // enclave running on the same platform, pass 0 instead. This uses the
    // EREPORT instruction to generate this enclave's local report.
    // Both kinds of reports can be verified using the oe_verify_report
    // function.
    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        sha256, // Store sha256 in report_data field
        sizeof(sha256),
        NULL, // opt_params must be null
        0,
        &temp_buf,
        remote_report_buf_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_get_report failed.");
        goto exit;
    }
    *remote_report_buf = temp_buf;
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

    // While attesting, the remote report being attested must not be tampered
    // with. Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(remote_report, remote_report_size))
    {
        TRACE_ENCLAVE("Cannot attest remote report in host memory. Unsafe.");
        goto exit;
    }

    // 1)  Validate the report's trustworthiness
    // Verify the remote report to ensure its authenticity.
    result =
        oe_verify_report(remote_report, remote_report_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_verify_report failed (%s).\n", oe_result_str(result));
        goto exit;
    }

    // 2) validate the enclave identity's signed_id is the hash of the public
    // signing key that was used to sign an enclave. Check that the enclave was
    // signed by an trusted entity.
    if (memcmp(parsed_report.identity.signer_id, m_enclave_mrsigner, 32) != 0)
    {
        TRACE_ENCLAVE("identity.signer_id checking failed.");
        TRACE_ENCLAVE(
            "identity.signer_id %s", parsed_report.identity.signer_id);

        for (int i = 0; i < 32; i++)
        {
            TRACE_ENCLAVE(
                "m_enclave_mrsigner[%d]=0x%0x\n",
                i,
                (uint8_t)m_enclave_mrsigner[i]);
        }

        TRACE_ENCLAVE("\n\n\n");

        for (int i = 0; i < 32; i++)
        {
            TRACE_ENCLAVE(
                "parsedReport.identity.signer_id)[%d]=0x%0x\n",
                i,
                (uint8_t)parsed_report.identity.signer_id[i]);
        }
        TRACE_ENCLAVE("m_enclave_mrsigner %s", m_enclave_mrsigner);
        goto exit;
    }

    // Check the enclave's product id and security version
    // See enc.conf for values specified when signing the enclave.
    if (parsed_report.identity.product_id[0] != 1)
    {
        TRACE_ENCLAVE("identity.product_id checking failed.");
        goto exit;
    }

    if (parsed_report.identity.security_version < 1)
    {
        TRACE_ENCLAVE("identity.security_version checking failed.");
        goto exit;
    }

    // 3) Validate the report data
    //    The report_data has the hash value of the report data
    if (m_crypto->Sha256(data, data_size, sha256) != 0)
    {
        goto exit;
    }

    if (memcmp(parsed_report.report_data, sha256, sizeof(sha256)) != 0)
    {
        TRACE_ENCLAVE("SHA256 mismatch.");
        goto exit;
    }
    ret = true;
    TRACE_ENCLAVE("remote attestation succeeded.");
exit:
    return ret;
}
