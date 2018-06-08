// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "attestation.h"
#include <openenclave/bits/hexdump.h>
#include <openenclave/enclave.h>
#include <string.h>
#include "crypto.h"
#include "log.h"

/**
 * Generate a quote for the given data. The SHA256 digest of the data is stored
 * in the reportData field of the generated quote.
 */
bool GenerateQuote(
    const uint8_t* data,
    const uint32_t dataSize,
    uint8_t* quoteBuffer,
    uint32_t* quoteBufferSize)
{
    uint8_t sha256[32];
    Sha256(data, dataSize, sha256);

    OE_Result result = OE_GetReport(
        OE_REPORT_OPTIONS_REMOTE_ATTESTATION,
        sha256, // Store sha256 in reportData field
        sizeof(sha256),
        NULL, // optParams must be null
        0,
        quoteBuffer,
        quoteBufferSize);

    if (result != OE_OK)
    {
        ENC_DEBUG_PRINTF("OE_GetReport failed.");
        return false;
    }

    ENC_DEBUG_PRINTF("GenerateQuote succeeded.");
    return result == OE_OK;
}

/**
 * Attest the given quote and accompanying data. The quote is first attested
 * using the OE_VerifyReport API. This ensures the authenticity of the enclave
 * that generated the quote. Next the mrsigner and mrenclave values are tested
 * to establish trust of the enclave that generated the quote. Next the validity
 * of accompanying data is ensured by comparing its SHA256 digest against the
 * reportData field.
 */
bool AttestQuote(
    const uint8_t* quote,
    uint32_t quoteSize,
    const uint8_t* data,
    uint32_t dataSize)
{
    // While attesting, the quote being attested must not be tampered with.
    // Ensure that it has been copied over to the enclave.
    if (!OE_IsWithinEnclave(quote, quoteSize))
    {
        ENC_DEBUG_PRINTF("Cannot attest quote in host memory. Unsafe.");
        return false;
    }

    // Verify the quote to ensure its authenticity.
    OE_Report parsedReport = {0};
    OE_Result result = OE_VerifyReport(quote, quoteSize, &parsedReport);
    if (result != OE_OK)
    {
        ENC_DEBUG_PRINTF("OE_VerifyReport failed.");
        return false;
    }

    // TODO: mrsigner, mrenclave check.
    OE_HexDump(
        parsedReport.identity.authorID, sizeof(parsedReport.identity.authorID));
    // OE_HexDump(parsedReport.identity.,
    // sizeof(parsedReport.identity.authorID));

    // Check the enclave's product id and security version
    // See enc.conf for values specified when signing the enclave.
    if (parsedReport.identity.productID[0] != 1)
        return false;

    if (parsedReport.identity.securityVersion != 1)
        return false;

    uint8_t sha256[32];
    Sha256(data, dataSize, sha256);

    if (memcmp(parsedReport.reportData, sha256, sizeof(sha256)) != 0)
    {
        ENC_DEBUG_PRINTF("SHA256 mismatch.");
        return false;
    }

    ENC_DEBUG_PRINTF("Quote attestation succeeded.");
    return true;
}
