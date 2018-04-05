// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CERT_H
#define _OE_CERT_H

#include "../result.h"
#include "../types.h"

OE_EXTERNC_BEGIN

typedef struct _OE_Cert
{
    /* Internal private implementation */
    uint64_t impl[80];
} OE_Cert;

typedef struct _OE_CertChain
{
    /* Internal private implementation */
    uint64_t impl[80];
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
 * @param pemData zero-terminated PEM data
 * @param pemSize size of the PEM data (including the zero-terminator)
 * @param cert initialized certificate chain handle upon return
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
 * @param error string error if OE_VERIFY_FAILED was returned (can be null)
 *
 * @return OE_OK verify ok
 * @return OE_VERIFY_FAILED verify failed and error parameter initialized
 * @return OE_INVALID_PARAMETER
 * @return OE_FAILURE
 */
OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder for future capability */
    OE_VerifyCertError* error);

OE_EXTERNC_END

#endif /* _OE_CERT_H */
