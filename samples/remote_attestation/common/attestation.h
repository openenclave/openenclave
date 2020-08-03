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

    // Generate remote evidence for the given data.
    bool generate_remote_evidence(
        const uint8_t* data,
        size_t data_size,
        uint8_t** remote_evidence_buf,
        size_t* remote_evidence_buf_size);

    /**
     * Attest the given remote evidence and accompanying data. The remote
     * evidence is first attested using the oe_verify_evidence API. This ensures
     * the authenticity of the enclave that generated the remote evidence. Next
     * the mrsigner and mrenclave values are tested to establish trust of the
     * enclave that generated the remote evidence.
     */
    bool attest_remote_evidence(
        const uint8_t* remote_evidence,
        size_t remote_evidence_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
