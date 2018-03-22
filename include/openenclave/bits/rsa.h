// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RSA_H
#define _OE_RSA_H

#include "../result.h"
#include "../types.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of an RSA public key */
typedef struct _OE_RSA 
{
    /* Internal private implementation */
    uint64_t impl[4];
}
OE_RSA_KEY;

/**
 * Reads a public RSA key from PEM data.
 *
 * This function loads an RSA key from a data buffer that contains a PEM
 * representation of an RSA key with the following format.
 *
 *     -----BEGIN RSA PRIVATE KEY-----
 *     ...
 *     -----END RSA PRIVATE KEY-----
 *
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 * @param privateKey - private key structure (pass to OE_RSAFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAReadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA_KEY* privateKey);

/**
 * Reads a public RSA key from PEM data.
 *
 * This function loads an RSA key from a data buffer that contains a PEM
 * representation of an RSA key with the following format.
 *
 *     -----BEGIN PUBLIC KEY-----
 *     ...
 *     -----END PUBLIC KEY-----
 *
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 * @param publicKey - public key structure (pass to OE_RSAFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAReadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA_KEY* publicKey);

/**
 * Write an RSA private key to PEM format
 *
 * This function write an RSA private key to PEM representation, which has the
 * following format.
 *
 *     -----BEGIN RSA PRIVATE KEY-----
 *     ...
 *     -----END RSA PRIVATE KEY-----
 *
 * @param privateKey - private key structure
 * @param pemData - pointer to zero-terminated PEM key representation
 * @param pemSize - size of the pemData buffer including the zero-terminator
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAWritePrivateKeyToPEM(
    const OE_RSA_KEY* privateKey,
    void** pemData,
    size_t* pemSize);

/**
 * Write an RSA public key to PEM format
 *
 * This function write an RSA private key to PEM representation, which has the
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
OE_Result OE_RSAWritePublicKeyToPEM(
    const OE_RSA_KEY* publicKey,
    void** pemData,
    size_t* pemSize);

/**
 * Releases an RSA key structure
 *
 * This function releases an RSA key structure that was created by one of the
 * functions in this module.
 *
 * @param key - pointer to RSA public key struture.
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAFree(OE_RSA_KEY* key);

/**
 * Sign a message with the given RSA private key
 *
 * This function signs a message (with the given hash) with an RSA private
 * key.
 *
 * @param privateKey - RSA private key
 * @param hash - SHA-256 hash of the message being signed
 * @param signature - resulting signature
 * @param signatureSize - size in bytes of the expected signature
 *
 * @return OE_OK if the signing operation was successful
 */
OE_Result OE_RSASign(
    const OE_RSA_KEY* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize);

/**
 * Verify that a message was signed by a given RSA key
 *
 * This function verifies that a message (with the given hash) was signed by a
 * a given RSA key.
 *
 * @param publicKey - RSA public key
 * @param hash - SHA-256 hash of the message being verified
 * @param signature - expected signature
 * @param signatureSize - size in bytes of the expected signature
 *
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_RSAVerify(
    const OE_RSA_KEY* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize);

/**
 * Generate an RSA private-public key pair
 *
 * This function generates an RSA private-public key pair from the given
 * parameters.
 *
 * @param bits - the number of bits in the key (power of two)
 * @param exponent - the exponent for this key
 * @param privateKey - generated private key
 * @param publicKey - generated public key
 *
 * @return OE_OK on success
 */
OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA_KEY* privateKey,
    OE_RSA_KEY* publicKey);

OE_EXTERNC_END

#endif /* _OE_RSA_H */
