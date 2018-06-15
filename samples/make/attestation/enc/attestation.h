// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
#define OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

#include <openenclave/enclave.h>

/**
 * Generate a quote for the given data. The SHA256 digest of the data is stored
 * in the report_data field of the generated quote.
 */
bool GenerateQuote(
    const uint8_t* data,
    uint32_t data_size,
    uint8_t* quote_buffer,
    uint32_t* quote_buffer_size);

/**
 * Attest the given quote and accompanying data. The quote is first attested
 * using the oe_verify_report API. This ensures the authenticity of the enclave
 * that generated the quote. Next the mrsigner and mrenclave values are tested
 * to establish trust of the enclave that generated the quote. Next the validity
 * of accompanying data is ensured by comparing its SHA256 digest against the
 * report_data field.
 */
bool AttestQuote(
    const uint8_t* quote,
    uint32_t quote_size,
    const uint8_t* data,
    uint32_t data_size);

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
