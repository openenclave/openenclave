// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
#define OE_SAMPLES_ATTESTATION_HOST_ECALLS_H

#include <openenclave/host.h>

#include "../args.h"

// Wrappers for Enclave function calls.

// Fetch the remote report and the public key from the enclave
RemoteReportWithPubKey* GetRemoteReportWithPubKey(oe_enclave_t* enclave);

// Ask the enclave to attest and store the public key of another enclave
oe_result_t VerifyReportAndSetPubKey(
    oe_enclave_t* enclave,
    RemoteReportWithPubKey* reportWithPubKey);

// Fetch encrypted data from the enclave
oe_result_t GenerateEncryptedMessage(
    oe_enclave_t* enclave,
    uint8_t** data,
    size_t* size);

// Send encrypted data to the enclave
oe_result_t ProcessEncryptedMessage(
    oe_enclave_t* enclave,
    const uint8_t* data,
    size_t size);

#endif // OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
