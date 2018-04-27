// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RSA_H
#define _OE_RSA_H

#include "../result.h"
#include "../types.h"
#include "hash.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a private RSA key */
typedef struct _OE_RSAPrivateKey
{
    /* Internal implementation */
    uint64_t impl[4];
} OE_RSAPrivateKey;

/* Opaque representation of a public RSA key */
typedef struct _OE_RSAPublicKey
{
    /* Internal implementation */
    uint64_t impl[4];
} OE_RSAPublicKey;

/**
 * Reads a private RSA key from PEM data
 *
 * This function reads a private RSA key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN RSA PRIVATE KEY-----
 *     ...
 *     -----END RSA PRIVATE KEY-----
 *
 * The caller is responsible for releasing the key by passing it to
 * OE_RSAPrivateKeyFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param privateKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPrivateKey* privateKey);

/**
 * Reads a public RSA key from PEM data
 *
 * This function reads a public RSA key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * The caller is responsible for releasing the key by passing it to
 * OE_RSAPublicKeyFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param publicKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* publicKey);

/**
 * Writes a private RSA key to PEM format
 *
 * This function writes a private RSA key to PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN RSA PRIVATE KEY-----
 *     ...
 *     -----END RSA PRIVATE KEY-----
 *
 * @param privateKey key to be written
 * @param pemData buffer where PEM data will be written
 * @param[in,out] pemSize buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_RSAPrivateKeyWritePEM(
    const OE_RSAPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize);

/**
 * Writes a public RSA key to PEM format
 *
 * This function writes a public RSA key to PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * @param publicKey key to be written
 * @param pemData buffer where PEM data will be written
 * @param[in,out] pemSize buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_RSAPublicKeyWritePEM(
    const OE_RSAPublicKey* publicKey,
    uint8_t* pemData,
    size_t* pemSize);

/**
 * Releases an RSA private key
 *
 * This function releases the given RSA private key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAPrivateKeyFree(OE_RSAPrivateKey* privateKey);

/**
 * Releases an RSA public key
 *
 * This function releases the given RSA public key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAPublicKeyFree(OE_RSAPublicKey* publicKey);

/**
 * Digitally signs a message with a private RSA key
 *
 * This function uses a private RSA key to sign a message with the given hash.
 *
 * @param privateKey private RSA key of signer
 * @param hashType type of hash parameter
 * @param hashData hash of the message being signed
 * @param hashSize size of the hash data
 * @param signature signature buffer
 * @param[in,out] signatureSize buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
OE_Result OE_RSAPrivateKeySign(
    const OE_RSAPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize);

/**
 * Verifies that a message was signed by an RSA key
 *
 * This function verifies that the message with the given hash was signed by the
 * given RSA key.
 *
 * @param publicKey public RSA key of signer
 * @param hashType type of hash parameter
 * @param hashData hash of the signed message
 * @param hashSize size of the hash data
 * @param signature expected signature
 * @param signatureSize size of the expected signature
 *
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_RSAPublicKeyVerify(
    const OE_RSAPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize);

/**
 * Generates an RSA private-public key pair
 *
 * This function generates an RSA private-public key pair from the given
 * parameters.
 *
 * @param bits the number of bits in the key
 * @param exponent the exponent for this key
 * @param privateKey generated private key
 * @param publicKey generated public key
 *
 * @return OE_OK on success
 */
OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey);

/**
 * Get the modulus from a public RSA key.
 *
 * This function gets the modulus from a public RSA key. The modulus bytes
 * are written to **buffer**.
 *
 * @param publicKey key whose key bytes are fetched.
 * @param buffer buffer where modulus is written (may be null).
 * @param bufferSize[in,out] buffer size on input; actual size on output.
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **bufferSize** contains
 *         the required size.
 */
OE_Result OE_RSAPublicKeyGetModulus(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize);

/**
 * Get the exponent from a public RSA key.
 *
 * This function gets the exponent from a public RSA key. The exponent bytes
 * are written to **buffer**.
 *
 * @param publicKey key whose key bytes are fetched.
 * @param buffer buffer where exponent is written (may be null).
 * @param bufferSize[in,out] buffer size on input; actual size on output.
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **bufferSize** contains
 *         the required size.
 */
OE_Result OE_RSAPublicKeyGetExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize);

OE_EXTERNC_END

#endif /* _OE_RSA_H */
