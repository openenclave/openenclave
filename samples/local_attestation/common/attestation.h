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
    uint8_t* m_enclave_mrsigner;

  public:
    Attestation(Crypto* crypto, uint8_t* enclave_mrsigner);

    // Generate evidence for the given data.
    bool generate_local_attestation_evidence(
        uint8_t* target_info_buffer,
        size_t target_info_size,
        const uint8_t* data,
        size_t data_size,
        uint8_t** evidence_buffer,
        size_t* local_evidence_buffer_size);

    /**
     * Attest the given evidence and accompanying data. The evidence
     * is first attested using the oe_verify_evidence API. This ensures the
     * authenticity of the enclave that generated the evidence. Next the
     * mrsigner and mrenclave values are tested to establish trust of the
     * enclave that generated the evidence.
     */
    bool attest_local_evidence(
        const uint8_t* local_evidence,
        size_t evidence_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
