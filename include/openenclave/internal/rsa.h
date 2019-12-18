// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_RSA_H
#define _OE_RSA_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include "crypto/hash.h"
#include "crypto/sha.h"

OE_EXTERNC_BEGIN

/* Opaque representation of a private RSA key */
typedef struct _oe_rsa_private_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_rsa_private_key_t;

/* Opaque representation of a public RSA key */
typedef struct _oe_rsa_public_key
{
    /* Internal implementation */
    uint64_t impl[4];
} oe_rsa_public_key_t;

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
 * oe_rsa_private_key_free().
 *
 * @param private_key initialized key handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size);

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
 * oe_rsa_public_key_free().
 *
 * @param public_key initialized key handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_size);

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
 * @param private_key key to be written
 * @param pem_data buffer where PEM data will be written
 * @param[in,out] pem_size buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size);

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
 * @param public_key key to be written
 * @param pem_data buffer where PEM data will be written
 * @param[in,out] pem_size buffer size (in); PEM data size (out)
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL PEM buffer is too small
 */
oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size);


/**
 * Reads a public RSA key from openssl engine using key id 
 *
 * The caller is responsible for releasing the key by passing it to
 * oe_rsa_public_key_free().
 *
 * @param public_key initialized key handle upon return
 * @param engine_id        zero-terminated string designating the openssl engine
 * @param engine_load_path zero-terminated string designating the openssl engine file system location
 * @param key_id           zero-terminated string designating the key to the openssl engine. 
 *
 * @return OE_OK upon success
 */
oe_result_t oe_rsa_private_key_from_engine(
    oe_rsa_private_key_t* private_key,
    const char *engine_id,
    const char *engine_load_path,
    const char *key_id);


/**
 * Releases an RSA private key
 *
 * This function releases the given RSA private key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key);

/**
 * Releases an RSA public key
 *
 * This function releases the given RSA public key.
 *
 * @param key handle of key being released
 *
 * @return OE_OK upon success
 */
oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key);

/**
 * Digitally signs a message with a private RSA key
 *
 * This function uses a private RSA key to sign a message with the given hash.
 *
 * @param private_key private RSA key of signer
 * @param hash_type type of hash parameter
 * @param hash_data hash of the message being signed
 * @param hash_size size of the hash data
 * @param signature signature buffer
 * @param[in,out] signature_size buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size);

/**
 * Verifies that a message was signed by an RSA key
 *
 * This function verifies that the message with the given hash was signed by the
 * given RSA key.
 *
 * @param public_key public RSA key of signer
 * @param hash_type type of hash parameter
 * @param hash_data hash of the signed message
 * @param hash_size size of the hash data
 * @param signature expected signature
 * @param signature_size size of the expected signature
 *
 * @return OE_OK if the message was signed with the given certificate
 */
oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size);

/**
 * Get the modulus from a public RSA key.
 *
 * This function gets the modulus from a public RSA key. The modulus is
 * written to **buffer**.
 *
 * @param public_key key whose modulus is fetched.
 * @param buffer buffer where modulus is written (may be null).
 * @param buffer_size[in,out] buffer size on input; actual size on output.
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **buffer_size** contains
 *         the required size.
 */
oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size);

/**
 * Get the exponent from a public RSA key.
 *
 * This function gets the exponent from a public RSA key. The exponent is
 * written to **buffer**.
 *
 * @param public_key key whose exponent is fetched.
 * @param buffer buffer where exponent is written (may be null).
 * @param buffer_size[in,out] buffer size on input; actual size on output.
 *
 * @return OE_OK upon success
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **buffer_size** contains
 *         the required size.
 */
oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size);

/**
 * Determine whether two RSA public keys are identical.
 *
 * This function determines whether two RSA public keys are identical.
 *
 * @param public_key1 first key.
 * @param public_key2 second key.
 * @param equal[out] true if the keys are identical.
 *
 * @return OE_OK successful and **equal** is either true or false.
 * @return OE_INVALID_PARAMETER a parameter was invalid.
 *
 */
oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal);

OE_EXTERNC_END

#endif /* _OE_RSA_H */
