// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_EC_H
#define _OE_EC_H

#include "../result.h"
#include "../types.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of an EC public key */
typedef struct _OE_EC 
{
    /* Internal private implementation */
    uint64_t impl[4];
}
OE_EC_KEY;

/**
 * Reads a public EC key from PEM data.
 *
 * This function loads an EC key from a data buffer that contains a PEM
 * representation of an EC key with the following format.
 *
 *     -----BEGIN EC PRIVATE KEY-----
 *     ...
 *     -----END EC PRIVATE KEY-----
 *
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 * @param privateKey - private key structure (pass to OE_ECFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECReadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC_KEY* privateKey);

/**
 * Reads a public EC key from PEM data.
 *
 * This function loads an EC key from a data buffer that contains a PEM
 * representation of an EC key with the following format.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 * @param publicKey - public key structure (pass to OE_ECFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECReadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC_KEY* publicKey);

/**
 * Write an EC private key to PEM format
 *
 * This function writes an EC private key to PEM representation, which has the
 * following format.
 *
 *     -----BEGIN EC PRIVATE KEY-----
 *     ...
 *     -----END EC PRIVATE KEY-----
 *
 * @param privateKey - private key structure
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECWritePrivateKeyToPEM(
    const OE_EC_KEY* privateKey,
    void** pemData,
    size_t* pemSize);

/**
 * Write an EC public key to PEM format
 *
 * This function writes an EC private key to PEM representation, which has the
 * following format.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * @param publicKey - public key structure
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECWritePublicKeyToPEM(
    const OE_EC_KEY* publicKey,
    void** pemData,
    size_t* pemSize);

/**
 * Releases an EC key structure
 *
 * This function releases an EC public key sturcture that was created
 * by one of the functions in this module.
 *
 * @param key - pointer to EC public key struture.
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECFree(OE_EC_KEY* key);

/**
 * Sign a message with the given EC private key
 *
 * This function signs a message (with the given hash) with an EC private
 * key.
 *
 * @param privateKey - EC private key
 * @param hash - SHA-256 hash of the message being signed
 * @param signature - resulting signature
 * @param signatureSize - size in bytes of the resulting signature
 *
 * @return OE_OK if the signing operation was successful
 */
OE_Result OE_ECSign(
    const OE_EC_KEY* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize);

/**
 * Verify that a message was signed by a given EC key
 *
 * This function verifies that a message (with the given hash) was signed by a
 * a given EC key.
 *
 * @param publicKey - EC public key
 * @param hash - SHA-256 hash of the message being verified
 * @param signature - expected signature
 * @param signatureSize - size in bytes of the expected signature
 *
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_ECVerify(
    const OE_EC_KEY* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize);

/**
 * Generate an EC private-public key pair
 *
 * This function generate an EC private-public key pair from the given
 * parameters.
 *
 * @param curveName - EC curve name (e.g., "secp521r1")
 * @param privateKey - generate private key
 * @param publicKey - generate public key
 *
 * @return OE_OK on success
 */
OE_Result OE_ECGenerate(
    const char* curveName,
    OE_EC_KEY* privateKey,
    OE_EC_KEY* publicKey);

OE_EXTERNC_END

#endif /* _OE_EC_H */
