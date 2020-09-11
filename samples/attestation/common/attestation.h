// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
#define OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

#include <openenclave/enclave.h>
#include "crypto.h"

#define ENCLAVE_SECRET_DATA_SIZE 16
class Attestation
{
  private:
    Crypto* m_crypto;
    uint8_t* m_enclave_signer_id;

  public:
    Attestation(Crypto* crypto, uint8_t* enclave_signer_id);

    // Get format settings.
    bool get_format_settings(
        const oe_uuid_t* format_id,
        uint8_t** format_settings_buffer,
        size_t* format_settings_buffer_size);

    // Generate evidence for the given data.
    bool generate_attestation_evidence(
        const oe_uuid_t* format_id,
        uint8_t* format_settings,
        size_t format_settings_size,
        const uint8_t* data,
        size_t data_size,
        uint8_t** evidence,
        size_t* evidence_size);

    /**
     * Attest the given evidence and accompanying data. The evidence
     * is first attested using the oe_verify_evidence API. This ensures the
     * authenticity of the enclave that generated the evidence. Next the enclave
     * signer_id and unique_id values are tested to establish trust of the
     * enclave that generated the evidence.
     */
    bool attest_attestation_evidence(
        const oe_uuid_t* format_id,
        const uint8_t* evidence,
        size_t evidence_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
