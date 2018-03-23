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
    uint64_t impl[128];
} OE_Cert;

typedef struct _OE_CertChain
{
    /* Internal private implementation */
    uint64_t impl[128];
} OE_CertChain;

typedef struct _OE_CRL OE_CRL;

/* Error message type for OE_VerifyCertError() function */
typedef struct _OE_VerifyCertError
{
    char buf[1024];
} OE_VerifyCertError;

/**
 * Read a certificate from PEM format.
 *
 * This function reads a certificate from PEM data in the following PEM
 * format.
 *
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *
 * @param pem - the certificate as zero-terminated PEM data
 * @param cert - pointer to certificate upon return
 *
 * @return OE_OK load was successful
 */
OE_Result OE_CertReadPEM(const void* pemData, size_t pemSize, OE_Cert* cert);

/**
 * Read a certificate chain from PEM format.
 *
 * This function reads a certificate chain from PEM data in the following PEM
 * format.
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
 * @param pem - the certificate as zero-terminated PEM data
 * @param chain - pointer to certificate chain upon return
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
 * This function releases a certificate structure.
 *
 * @param cert - pointer to certificate
 *
 * @return OE_OK load was successful
 */
OE_Result OE_CertFree(OE_Cert* cert);

/**
 * Releases a certificate chain
 *
 * This function releases all certificates in a certificate chain
 *
 * @param chain - pointer to certificate chain
 *
 * @return OE_OK load was successful
 */
OE_Result OE_CertChainFree(OE_CertChain* chain);

/**
 * Verify the given certificate against a certificate chain.
 *
 * This function verifies that the certificate given by **cert** against
 * a CA chain of certificates given by **chain**.
 * in PEM format as shown below.
 *
 * @param cert - the certificate
 * @param chain - the certificate chain
 * @param crl - the certificate revocation chain
 * @param error - string error if OE_VERIFY_FAILED returned (may be null).
 *        The caller is responsible for passing this string to free().
 *
 * @return OE_OK -- verify ok
 * @return OE_VERIFY_FAILED -- verify failed
 * @return OE_INVALID_PARAMTER -- null parameter
 * @return OE_FAILURE -- general failure
 */
OE_Result OE_CertVerify(
    OE_Cert* cert,
    OE_CertChain* chain,
    OE_CRL* crl, /* ATTN: placeholder for future capability */
    OE_VerifyCertError* error);

OE_EXTERNC_END

#endif /* _OE_CERT_H */
