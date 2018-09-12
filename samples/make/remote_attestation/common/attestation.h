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
    Crypto* m_pCrypto;
    uint8_t* m_pEnclaveMRSigner;

  public:
    Attestation(Crypto* pCrypto, uint8_t* enclaveMRSigner);

    // Generate a remote report for the given data. The SHA256 digest of the
    // data is stored
    // in the report_data field of the generated remote report.
    bool GenerateRemoteReport(
        const uint8_t* data,
        size_t dataSize,
        uint8_t* remoteReportBuffer,
        size_t* remoteReportBufferSize);

    /**
     * Attest the given remote report and accompanying data. The remote report
     * is first attested using the oe_verify_report API. This ensures the
     * authenticity of the enclave that generated the remote report. Next the
     * mrsigner and mrenclave values are tested to establish trust of the
     * enclave that generated the remote report. Next the validity of
     * accompanying data is ensured by comparing its SHA256 digest against the
     * report_data field.
     */
    bool AttestRemoteReport(
        const uint8_t* remoteReport,
        size_t remoteReportSize,
        const uint8_t* data,
        size_t dataSize);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
