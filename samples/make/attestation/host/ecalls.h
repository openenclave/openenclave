// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
#define OE_SAMPLES_ATTESTATION_HOST_ECALLS_H

#include <openenclave/host.h>

#include "../args.h"

/**
 * Wrappers for Enclave function calls.
 */

/**
 * Fetch the quoted public key from the enclave.
 */
QuotedPublicKey* GetPublicKey(oe_enclave_t* enclave);

/**
 * Ask the enclave to attest and store the public key of another enclave.
 */
void StorePublicKey(oe_enclave_t* enclave, QuotedPublicKey* quotedPublicKey);

/**
 * Fetch encrypted data from the enclave.
 */
void GenerateEncryptedData(oe_enclave_t* enclave, uint8_t** data, size_t* size);

/**
 * Send encrypted data to the enclave.
 */
void ProcessEncryptedData(
    oe_enclave_t* enclave,
    const uint8_t* data,
    size_t size);

#endif // OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
