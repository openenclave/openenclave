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
 * @param private_key initialized key handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size);

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
 * @param public_key initialized key handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size);

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
 * @param private_key key to be written
 * @param pem_data buffer where PEM data will be written
 * @param[in,out] pem_size buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size);

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
 * @param public_key key to be written
 * @param pem_data buffer where PEM data will be written
 * @param[in,out] pem_size buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size);

/**
 * Releases a private EC key
 *
 * This function releases the given EC private key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key);

/**
 * Releases a public EC key
 *
 * This function releases the given EC public key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key);

/**
 * Digitally signs a message with a private EC key
 *
 * This function uses a private EC key to sign a message with the given hash.
 *
 * @param private_key private EC key of signer
 * @param hash_type type of hash parameter
 * @param hash_data hash of the message being signed
 * @param hash_size size of the hash data
 * @param signature signature buffer
 * @param[in,out] signature_size buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size);

/**
 * Verifies that a message was signed by an EC key
 *
 * This function verifies that the message with the given hash was signed by the
 * given EC key.
 *
 * @param public_key public EC key of signer
 * @param hash_type type of hash parameter
 * @param hash_data hash of the signed message
 * @param hash_size size of the hash data
 * @param signature expected signature
 * @param signature_size size of the expected signature
 *
 * @return OE_OK if the message was signed with the given certificate
 */
oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size);

/**
 * Generates an EC private-public key pair
 *
 * This function generates an EC private-public key pair from the given
 * parameters.
 *
 * @param ec_type type of elliptical curve to be generated
 * @param private_key generated private key
 * @param public_key generated public key
 *
 * @return OE_OK on success
 */
oe_result_t oe_ec_generate_key_pair(
    oe_ec_type_t ec_type,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key);

/*
 * Computes an EC private-public key from a given private key
 *
 * Given an elliptic curve and a byte array representing the private key as a
 * big endian number, calculates the public key and exports both keys as
 * oe_ec_*_key_t structs.
 *
 * @param curve type of elliptical curve to be generated
 * @param private_key_buf the big endian number representing the private key
 * @param private_key_buf_size size_t the size of private_buf
 * @param private_key the output private key parameter
 * @param public_key the output public key parameter
 */
oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t curve,
    const uint8_t* private_key_buf,
    size_t private_key_buf_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key);

/**
 * Determine whether two EC public keys are identical.
 *
 * This function determines whether two EC public keys are identical.
 *
 * @param public_key1 first key.
 * @param public_key2 second key.
 * @param equal[out] true if the keys are identical.
 *
 * @return OE_OK successful and **equal** is either true or false.
 * @return OE_INVALID_PARAMETER a parameter was invalid.
 */
oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal);

/**
 * Initializes a public key from X and Y coordinates.
 *
 * This function initializes an EC public key from X and Y coordinates in
 * uncompressed format.
 *
 * @param public_key key which is initialized.
 * @param ec_type type of elliptical curve to create.
 * @param x_data the bytes for the X coordinate
 * @param x_size the size of the x_data buffer
 * @param y_data the bytes for the Y coordinate
 * @param y_size the size of the y_data buffer
 *
 * @return OE_OK upon success
 * @return OE_FAILED on failure
 */
oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size);

/**
 * Converts binary ECDSA signature values to an DER-encoded signature.
 *
 * This function converts ECDSA signature values (r and s) to an
 * DER-encoded signature suitable as an input parameter to the
 * **oe_ec_public_key_verify()** function.
 *
 * @param signature the buffer that will contain the signature
 * @param signature_size[in,out] buffer size (in); signature size (out)
 * @param data the R coordinate in binary form
 * @param size the size of the R coordinate buffer
 * @param s_data the S coordinate in binary form
 * @param s_size the size of the S coordinate buffer
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER invalid parameter
 * @return OE_BUFFER_TOO_SMALL **signature** buffer is too small
 *         and **signature_size** contains the required size.
 */
oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signature_size,
    const uint8_t* data,
    size_t size,
    const uint8_t* s_data,
    size_t s_size);

OE_EXTERNC_END

#endif /* _OE_EC_H */
