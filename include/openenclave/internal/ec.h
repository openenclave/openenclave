// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_EC_H
#define _OE_EC_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include "hash.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a private EC key */
typedef struct _oe_ec_private_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_ec_private_key_t;

/* Opaque representation of a public EC key */
typedef struct _oe_ec_public_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_ec_public_key_t;

/* Supported CURVE types */
typedef enum oe_ec_type_t {
    OE_EC_TYPE_SECP256R1,
    __OE_EC_TYPE_MAX = OE_ENUM_MAX,
} oe_ec_type_t;

OE_STATIC_ASSERT(sizeof(oe_ec_type_t) == sizeof(unsigned int));

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
 * oe_ec_private_key_free().
 *
 * @param privateKey initialized key handle upon return
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* privateKey,
    const uint8_t* pemData,
    size_t pemSize);

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
 * oe_ec_public_key_free().
 *
 * @param publicKey initialized key handle upon return
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* publicKey,
    const uint8_t* pemData,
    size_t pemSize);

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
oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* privateKey,
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
oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* publicKey,
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
oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* privateKey);

/**
 * Releases a public EC key
 *
 * This function releases the given EC public key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* publicKey);

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
oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* privateKey,
    oe_hash_type_t hashType,
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
oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* publicKey,
    oe_hash_type_t hashType,
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
oe_result_t oe_ec_generate_key_pair(
    oe_ec_type_t ecType,
    oe_ec_private_key_t* privateKey,
    oe_ec_public_key_t* publicKey);

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
 */
oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* publicKey1,
    const oe_ec_public_key_t* publicKey2,
    bool* equal);

/**
 * Initializes a public key from X and Y coordinates.
 *
 * This function initializes an EC public key from X and Y coordinates in
 * uncompressed format.
 *
 * @param publicKey key which is initialized.
 * @param ecType type of elliptical curve to create.
 * @param xData the bytes for the X coordinate
 * @param xSize the size of the xData buffer
 * @param yData the bytes for the Y coordinate
 * @param ySize the size of the yData buffer
 *
 * @return OE_OK upon success
 * @return OE_FAILED on failure
 */
oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* publicKey,
    oe_ec_type_t ecType,
    const uint8_t* xData,
    size_t xSize,
    const uint8_t* yData,
    size_t ySize);

OE_EXTERNC_END

/**
 * Converts binary ECDSA signature values to an DER-encoded signature.
 *
 * This function converts ECDSA signature values (r and s) to an
 * DER-encoded signature suitable as an input parameter to the
 * **oe_ec_public_key_verify()** function.
 *
 * @param signature the buffer that will contain the signature
 * @param signatureSize[in,out] buffer size (in); signature size (out)
 * @param rData the R coordinate in binary form
 * @param rSize the size of the R coordinate buffer
 * @param sData the S coordinate in binary form
 * @param sSize the size of the S coordinate buffer
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER invalid parameter
 * @return OE_BUFFER_TOO_SMALL **signature** buffer is too small
 *         and **signatureSize** contains the required size.
 */
oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signatureSize,
    const uint8_t* rData,
    size_t rSize,
    const uint8_t* sData,
    size_t sSize);

#endif /* _OE_EC_H */
