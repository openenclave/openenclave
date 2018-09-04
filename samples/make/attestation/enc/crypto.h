// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H
#define OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H

#include <openenclave/enclave.h>

/**
 * Crypto demonstrates use of mbedtls within the enclave to generate keys and
 * perform encryption. In this sample, each enclave instance generates an
 * ephemeral 2048-bit RSA key pair and shares the public key with the other
 * instance. The other enclave instance then replies with data encrypted to the
 * provided public key.
 */

/** InitializeCrypto initializes the crypto module.
 */
bool InitializeCrypto(void);

/**
 * Get the public key for this enclave.
 */
void GetPublicKey(uint8_t pemPublicKey[512]);

/**
 * Compute the sha256 hash of given data.
 */
void Sha256(const uint8_t* data, size_t dataSize, uint8_t sha256[32]);

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
*/
bool Encrypt(
    const uint8_t* pemPublicKey,
    const uint8_t* data,
    size_t size,
    uint8_t* encryptedData,
    size_t* encryptedDataSize);

/**
 * Decrypt decrypts the given data using current enclave's private key.
 * Used to receive encrypted data from another enclave.
 */
bool Decrypt(
    const uint8_t* encryptedData,
    size_t encryptedDataSize,
    uint8_t* data,
    size_t* dataSize);

#endif // OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H
