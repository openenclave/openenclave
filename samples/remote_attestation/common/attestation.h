// Copyright (c) Microsoft Corporation. All rights reserved.
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

    // Generate a remote report for the given data. The SHA256 digest of the
    // data is stored in the report_data field of the generated remote report.
    bool generate_remote_report(
        const uint8_t* data,
        size_t data_size,
        uint8_t** remote_report_buf,
        size_t* remote_report_buf_size);

    /**
     * Attest the given remote report and accompanying data. The remote report
     * is first attested using the oe_verify_report API. This ensures the
     * authenticity of the enclave that generated the remote report. Next the
     * mrsigner and mrenclave values are tested to establish trust of the
     * enclave that generated the remote report. Next the validity of
     * accompanying data is ensured by comparing its SHA256 digest against the
     * report_data field.
     */
    bool attest_remote_report(
        const uint8_t* remote_report,
        size_t remote_report_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
