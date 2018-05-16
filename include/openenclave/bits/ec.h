// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_EC_H
#define _OE_EC_H

#include "../result.h"
#include "../types.h"
#include "hash.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a private EC key */
typedef struct _OE_ECPrivateKey
{
    /* Internal implementation */
    uint64_t impl[4];
} OE_ECPrivateKey;

/* Opaque representation of a public EC key */
typedef struct _OE_ECPublicKey
{
    /* Internal implementation */
    uint64_t impl[4];
} OE_ECPublicKey;

/* Supported CURVE types */
typedef enum OE_ECType { OE_EC_TYPE_SECP521R1, OE_EC_TYPE_SECP256R1 } OE_ECType;

/**
 * Reads a private EC key from PEM data
 *
 * This function reads a private EC key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN PRIVATE KEY-----
 *     ...
 *     -----END PRIVATE KEY-----
 *
 * The caller is responsible for releasing the key by passing it to
 * OE_ECPrivateKeyFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param privateKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey);

/**
 * Reads a public EC key from PEM data
 *
 * This function reads a public EC key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * The caller is responsible for releasing the key by passing it to
 * OE_ECPublicKeyFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param publicKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* publicKey);

/**
 * Writes a private EC key to PEM format
 *
 * This function writes a private EC key to PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN EC PRIVATE KEY-----
 *     ...
 *     -----END EC PRIVATE KEY-----
 *
 * @param privateKey key to be written
 * @param pemData buffer where PEM data will be written
 * @param[in,out] pemSize buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize);

/*ATTN*/

/**
 * Writes a public EC key to PEM format
 *
 * This function writes a public EC key to PEM data with the following PEM
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
OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* publicKey,
    uint8_t* pemData,
    size_t* pemSize);

/**
 * Releases a private EC key
 *
 * This function releases the given EC private key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* privateKey);

/**
 * Releases a public EC key
 *
 * This function releases the given EC public key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* publicKey);

/**
 * Digitally signs a message with a private EC key
 *
 * This function uses a private EC key to sign a message with the given hash.
 *
 * @param privateKey private EC key of signer
 * @param hashType type of hash parameter
 * @param hashData hash of the message being signed
 * @param hashSize size of the hash data
 * @param signature signature buffer
 * @param[in,out] signatureSize buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize);

/**
 * Verifies that a message was signed by an EC key
 *
 * This function verifies that the message with the given hash was signed by the
 * given EC key.
 *
 * @param publicKey public EC key of signer
 * @param hashType type of hash parameter
 * @param hashData hash of the signed message
 * @param hashSize size of the hash data
 * @param signature expected signature
 * @param signatureSize size of the expected signature
 *
 * @return OE_OK if the message was signed with the given certificate
 */
OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize);

/**
 * Generates an EC private-public key pair
 *
 * This function generates an EC private-public key pair from the given
 * parameters.
 *
 * @param ecType type of elliptical curve to be generated
 * @param privateKey generated private key
 * @param publicKey generated public key
 *
 * @return OE_OK on success
 */
OE_Result OE_ECGenerateKeyPair(
    OE_ECType ecType,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey);

/**
 * Get the key bytes from an EC public key
 *
 * This function gets the key bytes from an EC public key. The bytes
 * are written to the **buffer** parameter.
 *
 * @param publicKey key whose key bytes are fetched.
 * @param buffer buffer where bytes are written (may be null).
 * @param bufferSize[in,out] buffer size on input; actual size on output.
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **bufferSize** contains
 *         the required size.
 */
OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize);

/**
 * Determine whether two EC public keys are identical.
 *
 * This function determines whether two EC public keys are identical.
 *
 * @param publicKey1 first key.
 * @param publicKey2 second key.
 * @param equal[out] true if the keys are identical.
 *
 * @return OE_OK successful and **equal** is either true or false.
 * @return OE_INVALID_PARAMETER a parameter was invalid.
 *
 */
OE_Result OE_ECPublicKeyEqual(
    const OE_ECPublicKey* publicKey1,
    const OE_ECPublicKey* publicKey2,
    bool* equal);

/* the point is encoded as z||x||y, where z is the octet 0x04  */
OE_Result OE_ECPublicKeyFromBytes(
    OE_ECPublicKey* publicKey,
    OE_ECType ecType,
    const uint8_t* buffer,
    size_t bufferSize);

OE_EXTERNC_END

#endif /* _OE_EC_H */
