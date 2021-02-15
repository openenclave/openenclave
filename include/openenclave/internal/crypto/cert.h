// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CERT_H
#define _OE_CERT_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/rsa.h>
#include "../rsa.h"
#include "crl.h"
#include "ec.h"
#include "oid.h"

OE_EXTERNC_BEGIN

typedef struct _oe_cert
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_t;

typedef struct _oe_cert_chain
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_cert_chain_t;

/**
 * Read a certificate from PEM format
 *
 * This function reads a certificate from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *
 * The caller is responsible for releasing the certificate by passing it to
 * oe_cert_free().
 *
 * @param cert initialized certificate handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size);

/**
 * Read a certificate from DER format
 *
 * This function reads a certificate from DER data
 *
 * The caller is responsible for releasing the certificate by passing it to
 * oe_cert_free().
 *
 * @param cert initialized certificate handle upon return
 * @param der_data DER data
 * @param der_size size of the DER data
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_size);

/**
 * Read a certificate chain from PEM format.
 *
 * This function reads a certificate chain from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *
 * Each certificate in the chain is verified with respect to its predecessor in
 * the chain. If any such verification fails, this function returns an error.
 * The caller is responsible for releasing the certificate chain by passing it
 * to oe_cert_chain_free().
 *
 * @param chain initialized certificate chain handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_size);

/**
 * Releases a certificate
 *
 * This function releases the given certificate.
 *
 * @param cert handle of the certificate being released
 *
 * @return OE_OK certificate was successfully released
 */
oe_result_t oe_cert_free(oe_cert_t* cert);

/**
 * Releases a certificate chain
 *
 * This function releases the given certificate chain.
 *
 * @param chain handle of certificate chain being released
 *
 * @return OE_OK certificate chain was successfully released
 */
oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain);

/**
 * Verify the given certificate against a given certificate chain
 *
 * This function verifies the given certificate against the certificate
 * authority (CA), given by the certificate chain.
 *
 * @param cert verify this certificate
 * @param chain verify the certificate against this certificate chain
 * @param crls verify the certificate against these CRLs (may be null).
 * @param num_crls number of CRLs.
 *
 * @return OE_OK verify ok
 * @return OE_VERIFY_FAILED
 * @return OE_INVALID_PARAMETER
 * @return OE_FAILURE
 */
oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls);

/**
 * Get the RSA public key from a certificate.
 *
 * This function gets the RSA public key from the given certificate. If the
 * the certificate does not contain an RSA public key, this function returns
 * OE_PUBLIC_KEY_NOT_FOUND.
 *
 * @param cert the certificate whose RSA public key is sought.
 * @param public_key the handle of an RSA public key upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     key by passing it to **oe_rsa_public_key_free()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_PUBLIC_KEY_NOT_FOUND the certificate does not contain an RSA
 * public key
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key);

/**
 * Get the EC public key from a certificate.
 *
 * This function gets the EC public key from the given certificate. If the
 * the certificate does not contain an EC public key, this function returns
 * OE_PUBLIC_KEY_NOT_FOUND.
 *
 * @param cert the certificate whose EC public key is sought.
 * @param public_key the handle of an EC public key upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     key by passing it to **oe_ec_public_key_free()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_PUBLIC_KEY_NOT_FOUND the certificate does not contain an EC public
 * key
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key);

/**
 * Get the public key (in PEM format) from a certificate
 *
 * This function extracts the public key from the given certificate before
 * writing to a buffer in PEM format
 *
 * @param cert the certificate whose public key is sought
 * @param pem_data the buffer to hold returned public key in PEM foramt
 * @param pem_size size of of pem_data buffer
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_write_public_key_pem(
    const oe_cert_t* cert,
    uint8_t* pem_data,
    size_t* pem_size);

/**
 * Get the length of a certificate chain.
 *
 * This function gets the length of the certificate chain. This length
 * is the total number of certificates contained in the chain.
 *
 * @param chain the chain whose length is to be determined
 * @param length the certificate chain length on success or zero on failure
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length);

/**
 * Fetch the certificate with the given index from a certificate chain.
 *
 * This function fetches the certificate with the given index from a
 * certificate chain. The certificate with the highest index is the leaf
 * certificate. Use oe_cert_chain_get_length() to obtain the number of
 * certificates in the chain.
 *
 * @param chain the chain whose certificate is fetched.
 * @param index the index of the certificate to be fetched.
 * @param cert the handle of a certificate upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     certificate by passing it to **oe_cert_free()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_OUT_OF_BOUNDS the certificate index is out of bounds
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert);

/**
 * Fetch the root certificate from a certificate chain.
 *
 * This function fetches the root certificate from a certificate chain. The
 * root certificate is found by walking from the leaf certificate upwards
 * until a self-signed certificate is found. A self-signed certificate is one
 * in which the issuer-name and the subject-name are the same.
 *
 * @param chain the chain whose root certificate is fetched.
 * @param cert the handle of a certificate upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     certificate by passing it to **oe_cert_free()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_NOT_FOUND chain is empty or no self-signed certificate was found
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_chain_get_root_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert);

/**
 * Fetch the leaf certificate from a certificate chain.
 *
 * This function fetches the leaf certificate from a certificate chain.
 *
 * @param chain the chain whose leaf certificate is fetched.
 * @param cert the handle of a certificate upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     certificate by passing it to **oe_cert_free()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_NOT_FOUND certificate chain is empty
 * @return OE_FAILURE general failure
 */
oe_result_t oe_cert_chain_get_leaf_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert);

/**
 * Gets information about the X.509 certificate extension with the given OID.
 *
 * This function gets information about the X.509 certificate extension with
 * the given OID, obtaining the data and data size of the extension.
 *
 * @param cert[in] the certificate.
 * @param oid[in] the OID of the extension.
 * @param data[out] the data of the extension.
 * @param size[in,out] the data buffer size (in) or the actual data size (out).
 *
 * @return OE_OK success.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_NOT_FOUND an extension with the given OID was not found.
 * @return OE_BUFFER_TOO_SMALL the data buffer is too small and the **size**
 *         parameter contains the required size.
 * @return OE_FAILURE general failure.
 */
oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* size);

/**
 * Gets the URLs from the CRL-distribution-points extension.
 *
 * The extension whose OID is "2.5.29.31" contains the CRL distribution points.
 * This function obtains an array of URLs from this extension.
 *
 * @param cert[in] the certificate.
 * @param urls[out] the array of URLs upon return. This array and its entries
 *        overlay the space given by the **buffer** parameter.
 * @param num_urls the number of URLs found in the extension.
 * @param buffer the buffer that holds the URL array and its entries. This
 *        parameter may be null when **buffer_size** is zero. This buffer must
 *        be aligned on an 8-byte boundary since it contains the array of
 *        pointers to URLs.
 * @param buffer_size[in,out] the size of the buffer (in); the required size
 *        of the buffer (out).
 *
 * @return OE_OK success.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_BUFFER_TOO_SMALL the buffer is too small and the **buffer_size**
 *         parameter contains the required size.
 * @return OE_BAD_ALIGNMENT the buffer is not aligned on an 8-byte boundary.
 * @return OE_FAILURE general failure.
 */
oe_result_t oe_get_crl_distribution_points(
    const oe_cert_t* cert,
    char*** urls,
    size_t* num_urls,
    uint8_t* buffer,
    size_t* buffer_size);

/**
 * Gets the validation datetimes from the certificate.
 *
 * @param cert[in] the certificate.
 * @param not_before the date when the certificate validate starts (may be
 * null).
 * @param not_after the date at which this CRL should be considered invalid
 *        (may be null).
 */
oe_result_t oe_cert_get_validity_dates(
    const oe_cert_t* cert,
    oe_datetime_t* not_before,
    oe_datetime_t* not_after);

#ifdef OE_BUILD_ENCLAVE

typedef struct _oe_cert_config
{
    uint8_t* private_key_buf;
    size_t private_key_buf_size;
    uint8_t* public_key_buf;
    size_t public_key_buf_size;
    const unsigned char* subject_name;
    const unsigned char* issuer_name;
    unsigned char* date_not_valid_before;
    unsigned char* date_not_valid_after;
    uint8_t* ext_data_buf;
    size_t ext_data_buf_size;
    char* ext_oid;
    size_t ext_oid_size;
} oe_cert_config_t;

/* includes all the headers from version number to subject unique identifier of
 * a X509 certificate */
#define OE_MIN_CERT_SIZE 2048

oe_result_t oe_gen_custom_x509_cert(
    oe_cert_config_t* cert_config,
    unsigned char* cert_buf,
    size_t cert_buf_size,
    size_t* bytes_written);

#endif

OE_EXTERNC_END

#endif /* _OE_CERT_H */
