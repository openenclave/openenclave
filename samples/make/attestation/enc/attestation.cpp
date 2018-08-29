// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <string.h>

#include "attestation.h"
#include "crypto.h"
#include "log.h"

/**
 * Generate a quote for the given data. The SHA256 digest of the data is stored
 * in the report_data field of the generated quote.
 */
bool GenerateQuote(
    const uint8_t* data,
    const size_t dataSize,
    uint8_t* quoteBuffer,
    size_t* quoteBufferSize)
{
    uint8_t sha256[32];
    Sha256(data, dataSize, sha256);

    // To generate a quote that can be attested remotely by an enclave running
    // on a different platform, pass the OE_REPORT_OPTIONS_REMOTE_ATTESTATION
    // option. This uses the trusted quoting enclave to generate the report
    // based on this enclave's local report.
    // To generate a quote that just needs to be attested by another enclave
    // running on the same platform, pass 0 instead. This uses the EREPORT
    // instruction to generate this enclave's local report.
    // Both kinds of reports can be verified using the oe_verify_report
    // function.
    oe_result_t result = oe_get_report(
        OE_REPORT_OPTIONS_REMOTE_ATTESTATION,
        sha256, // Store sha256 in report_data field
        sizeof(sha256),
        NULL, // optParams must be null
        0,
        quoteBuffer,
        quoteBufferSize);

    if (result != OE_OK)
    {
        ENC_DEBUG_PRINTF("oe_get_report failed.");
        return false;
    }

    ENC_DEBUG_PRINTF("GenerateQuote succeeded.");
    return result == OE_OK;
}

// The SHA-256 hash of the public key in the private.pem file used to sign the
// enclave. This value is populated in the signer_id sub-field of a parsed
// oe_report_t's identity field.
const uint8_t g_MRSigner[] = {0xCA, 0x9A, 0xD7, 0x33, 0x14, 0x48, 0x98, 0x0A,
                              0xA2, 0x88, 0x90, 0xCE, 0x73, 0xE4, 0x33, 0x63,
                              0x83, 0x77, 0xF1, 0x79, 0xAB, 0x44, 0x56, 0xB2,
                              0xFE, 0x23, 0x71, 0x93, 0x19, 0x3A, 0x8D, 0x0A};
/**
 * Attest the given quote and accompanying data. The quote is first attested
 * using the oe_verify_report API. This ensures the authenticity of the enclave
 * that generated the quote. Next, to establish trust of the enclave that
 * generated the quote, the mrsigner, product_id, isvsvn values are checked to
 * see if they are predefined trusted values. Once the enclave's trust has been
 * established, the validity of accompanying data is ensured by comparing its
 * SHA256 digest against the report_data field.
 */
bool AttestQuote(
    const uint8_t* quote,
    size_t quoteSize,
    const uint8_t* data,
    size_t dataSize)
{
    // While attesting, the quote being attested must not be tampered with.
    // Ensure that it has been copied over to the enclave.
    if (!oe_is_within_enclave(quote, quoteSize))
    {
        ENC_DEBUG_PRINTF("Cannot attest quote in host memory. Unsafe.");
        return false;
    }

    // Verify the quote to ensure its authenticity.
    oe_report_t parsedReport = {0};
    oe_result_t result = oe_verify_report(quote, quoteSize, &parsedReport);
    if (result != OE_OK)
    {
        ENC_DEBUG_PRINTF("oe_verify_report failed.");
        return false;
    }

    // AuthorID is the hash of the public signing key that was used to sign an
    // enclave.
    // Check that the enclave was signed by an trusted entity.
    if (memcmp(
            parsedReport.identity.signer_id, g_MRSigner, sizeof(g_MRSigner)) !=
        0)
        return false;

    // Check the enclave's product id and security version
    // See enc.conf for values specified when signing the enclave.
    if (parsedReport.identity.product_id[0] != 1)
        return false;

    if (parsedReport.identity.security_version < 1)
        return false;

    uint8_t sha256[32];
    Sha256(data, dataSize, sha256);

    if (memcmp(parsedReport.report_data, sha256, sizeof(sha256)) != 0)
    {
        ENC_DEBUG_PRINTF("SHA256 mismatch.");
        return false;
    }

    ENC_DEBUG_PRINTF("Quote attestation succeeded.");
    return true;
}
