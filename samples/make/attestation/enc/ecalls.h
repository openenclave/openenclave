// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_ECALLS_H
#define OE_SAMPLES_ATTESTATION_ENC_ECALLS_H

#include <openenclave/enclave.h>

#include "../args.h"

/**
 * Return the public key of this enclave along with the enclave's quote. Another
 * enclave can use the quote to attest the enclave and verify the integrity of
 * the public key.
 */
OE_ECALL void GetPublicKey(GetPublicKeyArgs* arg);

/**
 * Attest and store the public key of another enclave.
 */
OE_ECALL void StorePublicKey(StorePublicKeyArgs* arg);

/**
 * Encrypt data for another enclave using the public key stored for it.
*/
OE_ECALL void GenerateEncryptedData(GenerateEncryptedDataArgs* arg);

/**
 * Process encrypted data.
*/
OE_ECALL void ProcessEncryptedData(ProcessEncryptedDataArgs* arg);

#endif // OE_SAMPLES_ATTESTATION_ENC_ECALLS_H
