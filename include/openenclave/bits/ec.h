// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_EC_H
#define _OE_EC_H

#include "../result.h"
#include "../types.h"
#include "hash.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a private or public EC key */
typedef struct _OE_EC_KEY
{
    /* Internal private implementation */
    uint64_t impl[4];
} OE_EC_KEY;

/* Supported CURVE types */
typedef enum OE_ECType { OE_EC_TYPE_SECP521R1 } OE_ECType;

/**
 * Reads a private EC key from PEM data
 *
 * This function reads a private EC key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN EC PRIVATE KEY-----
 *     ...
 *     -----END EC PRIVATE KEY-----
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param privateKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* privateKey);

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
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param publicKey initialized key handle upon return
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* publicKey);

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
 * @param[in,out] pemSize - buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_ECWritePrivateKeyPEM(
    const OE_EC_KEY* privateKey,
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
 * @param[in,out] pemSize - buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
OE_Result OE_ECWritePublicKeyPEM(
    const OE_EC_KEY* publicKey,
    uint8_t* pemData,
    size_t* pemSize);

/**
 * Releases an EC key
 *
 * This function releases the given EC key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
OE_Result OE_ECFree(OE_EC_KEY* key);

/**
 * Digitaly signs a message with a private EC key
 *
 * This function uses a private EC key to sign a message with the given hash.
 *
 * @param privateKey private EC key of signer
 * @param hashType type of hash parameter
 * @param hashData hash of the message being signed
 * @param hashSize size of the hash data
 * @param signature signature buffer
 * @param[in,out] signatureSize - buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
OE_Result OE_ECSign(
    const OE_EC_KEY* privateKey,
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
 * @return OE_OK if the message was signeded with the given certificate
 */
OE_Result OE_ECVerify(
    const OE_EC_KEY* publicKey,
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
 * @param ecType type of eliptical curve to be generated
 * @param privateKey generated private key
 * @param publicKey generated public key
 *
 * @return OE_OK on success
 */
OE_Result OE_ECGenerate(
    OE_ECType ecType,
    OE_EC_KEY* privateKey,
    OE_EC_KEY* publicKey);

OE_EXTERNC_END

#endif /* _OE_EC_H */
