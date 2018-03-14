// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RSA_H
#define _OE_RSA_H

#include "../result.h"
#include "../types.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of an RSA public key */
typedef struct _OE_RSA OE_RSA;

/**
 * Loads a public RSA key from PEM data.
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
 * @param key - key structure (pass to OE_RSAFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSALoadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA** key);

/**
 * Loads a public RSA key from PEM data.
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
 * @param key - key structure (pass to OE_RSAFree() to free)
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSALoadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize, /* ATTN: use zero-terminated PEM data */
    OE_RSA** key);

/**
 * Releases an RSA key structure
 *
 * This function releases an RSA public key sturcture that was created
 * by one of the functions in this module.
 *
 * @param key - pointer to RSA public key struture.
 *
 * @return OE_OK upon success
 */
void OE_RSAFree(OE_RSA* key);

/**
 * Sign a message with the given RSA private key
 *
 * This function signs a message (with the given hash) with an RSA private
 * key.
 *
 * @param key - RSA private key
 * @param hash - SHA-256 hash of the message being signed
 * @param signature - resulting signature
 *
 * @return OE_OK if the signing operation was successful
 */
OE_Result OE_RSASign(
    OE_RSA* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize);

/**
 * Verify that a message was signed by a given RSA key
 *
 * This function verifies that a message (with the given hash) was signed by a
 * a given RSA key.
 *
 * @param key - RSA public key
 * @param hash - SHA-256 hash of the message being verified
 * @param signature - expected signature
 *
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_RSAVerify(
    OE_RSA* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize);

/**
 * Generate an RSA private-public key pair
 *
 * This function generate an RSA private-public key pair from the given
 * parameters.
 *
 * @param privateKey - generate private key
 * @param publicKey - generate public key
 *
 * @return OE_OK on success
 */
OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA** privateKey,
    OE_RSA** publicKey);

OE_EXTERNC_END

#endif /* _OE_RSA_H */
