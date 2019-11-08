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

    // Generate a report for the given data. The SHA256 digest of the
    // data is stored in the report_data field of the generated report.
    bool generate_local_report(
        uint8_t* target_info_buffer,
        size_t target_info_size,
        const uint8_t* data,
        size_t data_size,
        uint8_t** report_buf,
        size_t* remote_report_buf_size);

    /**
     * Attest the given report and accompanying data. The report
     * is first attested using the oe_verify_report API. This ensures the
     * authenticity of the enclave that generated the report. Next the
     * mrsigner and mrenclave values are tested to establish trust of the
     * enclave that generated the report. Next the validity of
     * accompanying data is ensured by comparing its SHA256 digest against the
     * report_data field.
     */
    bool attest_local_report(
        const uint8_t* local_report,
        size_t report_size,
        const uint8_t* data,
        size_t data_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
