// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_RSA_H
#define _OE_RSA_H

#include "../result.h"
#include "../types.h"
#include "hash.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a public RSA key */
typedef struct _OE_RSA
{
    /* Internal private implementation */
    uint64_t impl[4];
} OE_RSA_KEY;

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
 * @param pemData - zero-terminated PEM data
 * @param pemSize - size of the PEM data (including the zero-terminator)
 * @param privateKey - initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* privateKey);

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
 * @param pemData - zero-terminated PEM data
 * @param pemSize - size of the PEM data (including the zero-terminator)
 * @param publicKey - initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* publicKey);

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
 * @param privateKey - key to be written
 * @param pemData - buffer where PEM data will be written
 * @param[in,out] pemSize - buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_RSAWritePrivateKeyPEM(
    const OE_RSA_KEY* privateKey,
    uint8_t* pemData,
    size_t* pemSize);

/*ATTN*/

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
 * @param publicKey - key to be written
 * @param pemData - buffer where PEM data will be written
 * @param[in,out] pemSize - buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_RSAWritePublicKeyPEM(
    const OE_RSA_KEY* publicKey,
    uint8_t* pemData,
    size_t* pemSize);

/**
 * Releases an RSA key
 *
 * This function releases the given RSA key.
 *
 * @param key - handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_RSAFree(OE_RSA_KEY* key);

/**
 * Digitaly signs a message with a private RSA key
 *
 * This function uses a private RSA key to sign a message with the given hash.
 *
 * @param privateKey - private RSA key of signer
 * @param hashType - type of hash parameter
 * @param hashData - hash of the message being signed
 * @param hashSize - size of the hash data
 * @param signature - signature buffer
 * @param[in,out] signatureSize - buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
OE_Result OE_RSASign(
    const OE_RSA_KEY* privateKey,
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
 * @param publicKey - public RSA key of signer
 * @param hashType - type of hash parameter
 * @param hashData - hash of the signed message
 * @param hashSize - size of the hash data
 * @param signature - expected signature
 * @param signatureSize - size of the expected signature
 *
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_RSAVerify(
    const OE_RSA_KEY* publicKey,
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
 * @param bits - the number of bits in the key
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
