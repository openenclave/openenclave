// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
#define OE_SAMPLES_ATTESTATION_HOST_ECALLS_H

#include <openenclave/host.h>
#include <openenclave/types.h>

#include "../args.h"

/**
 * Wrappers for Enclave function calls.
 */

/**
 * Initialize the enclave.
 */
void Initialize(OE_Enclave* enclave);

/**
 * Fetch the quoted public key from the enclave.
 */
QuotedPublicKey* GetPublicKey(OE_Enclave* enclave);

/**
 * Ask the enclave to attest and store the public key of another enclave.
 */
void StorePublicKey(OE_Enclave* enclave, QuotedPublicKey* quotedPublicKey);

/**
 * Fetch encrypted data from the enclave.
 */
void GenerateEncryptedData(OE_Enclave* enclave, uint8_t** data, uint32_t* size);

/**
 * Send encrypted data to the enclave.
 */
void ProcessEncryptedData(
    OE_Enclave* enclave,
    const uint8_t* data,
    uint32_t size);

#endif // OE_SAMPLES_ATTESTATION_HOST_ECALLS_H
