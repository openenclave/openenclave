// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CERT_H
#define _OE_CERT_H

#include <openenclave/result.h>
#include <openenclave/types.h>
#include "ec.h"
#include "rsa.h"

OE_EXTERNC_BEGIN

typedef struct _OE_Cert
{
    /* Internal private implementation */
    uint64_t impl[4];
} OE_Cert;

typedef struct _OE_CertChain
{
    /* Internal private implementation */
    uint64_t impl[4];
} OE_CertChain;

typedef struct _OE_CRL OE_CRL;

/* Error message type for OE_VerifyCertError() function */
typedef struct _OE_VerifyCertError
{
    /* Zero-terminated string error message */
    char buf[1024];
} OE_VerifyCertError;

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
 * OE_CertFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param cert initialized certificate handle upon return
 *
 * @return OE_OK load was successful
 */
OE_Result OE_CertReadPEM(const void* pemData, size_t pemSize, OE_Cert* cert);

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
 * to OE_CertChainFree().
 *
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param[out] chain initialized certificate chain handle upon return
 *
 * @return OE_OK load was successful
 */
OE_Result OE_CertChainReadPEM(
    const void* pemData,
    size_t pemSize,
    OE_CertChain* chain);

/**
 * Releases a certificate
 *
 * This function releases the given certificate.
 *
 * @param cert handle of the certificate being released
 *
 * @return OE_OK certificate was successfully released
 */
OE_Result OE_CertFree(OE_Cert* cert);

/**
 * Releases a certificate chain
 *
 * This function releases the given certificate chain.
 *
 * @param chain handle of certificate chain being released
 *
 * @return OE_OK certificate chain was successfully released
 */
OE_Result OE_CertChainFree(OE_CertChain* chain);

/**
 * Verify the given certificate against a given certificate chain
 *
 * This function verifies the given certificate against the certificate
 * authority (CA), given by the certificate chain.
 *
 * @param cert verify this certificate
 * @param chain verify the certificate against this certificate chain
 * @param crl verify the certificate against this CRL
 * @param error Optional. Holds the error message if this function failed.
 *
 * @return OE_OK verify ok
 * @return OE_VERIFY_FAILED
 * @return OE_INVALID_PARAMETER
 * @return OE_FAILURE
 */
OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder for future capability */
    OE_VerifyCertError* error);

/**
 * Get the RSA public key from a certificate.
 *
 * This function gets the RSA public key from the given certificate. If the
 * the certificate does not contain an RSA public key, this function returns
 * OE_WRONG_TYPE.
 *
 * @param cert the certificate whose RSA public key is sought.
 * @param publicKey the handle of an RSA public key upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     key by passing it to **OE_RSAPublicKeyFree()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_WRONG_TYPE the certificate does not contain an RSA public key
 * @return OE_FAILURE general failure
 */
OE_Result OE_CertGetRSAPublicKey(
    const OE_Cert* cert,
    OE_RSAPublicKey* publicKey);

/**
 * Get the EC public key from a certificate.
 *
 * This function gets the EC public key from the given certificate. If the
 * the certificate does not contain an EC public key, this function returns
 * OE_WRONG_TYPE.
 *
 * @param cert the certificate whose EC public key is sought.
 * @param publicKey the handle of an EC public key upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     key by passing it to **OE_ECPublicKeyFree()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_WRONG_TYPE the certificate does not contain an EC public key
 * @return OE_FAILURE general failure
 */
OE_Result OE_CertGetECPublicKey(const OE_Cert* cert, OE_ECPublicKey* publicKey);

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
OE_Result OE_CertChainGetLength(const OE_CertChain* chain, size_t* length);

/**
 * Fetch the certificate with the given index from a certificate chain.
 *
 * This function fetches the certificate with the given index from a
 * certificate chain. The certificate with the highest index is the leaf
 * certificate. Use OE_CertChainGetLength() to obtain the number of
 * certificates in the chain.
 *
 * @param chain the chain whose certificate is fetched.
 * @param index the index of the certificate to be fetched.
 * @param cert the handle of a certificate upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     certificate by passing it to **OE_CertFree()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_OUT_OF_BOUNDS the certificate index is out of bounds
 * @return OE_FAILURE general failure
 */
OE_Result OE_CertChainGetCert(
    const OE_CertChain* chain,
    size_t index,
    OE_Cert* cert);

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
 *     certificate by passing it to **OE_CertFree()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_NOT_FOUND no self-signed certificate was found
 * @return OE_FAILURE general failure
 */
OE_Result OE_CertChainGetRootCert(const OE_CertChain* chain, OE_Cert* cert);

/**
 * Fetch the leaf certificate from a certificate chain.
 *
 * This function fetches the leaf certificate from a certificate chain.
 *
 * @param chain the chain whose leaf certificate is fetched.
 * @param cert the handle of a certificate upon successful return.
 *     If successful, the caller is responsible for eventually releasing the
 *     certificate by passing it to **OE_CertFree()**.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
OE_Result OE_CertChainGetLeafCert(const OE_CertChain* chain, OE_Cert* cert);

OE_EXTERNC_END

#endif /* _OE_CERT_H */
