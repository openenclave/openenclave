// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/pem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#include "../magic.h"
#include "bcrypt.h"
#include "crl.h"
#include "ec.h"
#include "key.h"
#include "pem.h"
#include "rsa.h"
#include "util.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define _OE_CERT_CHAIN_LENGTH_ANY 0

static const DWORD _OE_DEFAULT_GET_CRL_FLAGS =
    CERT_STORE_SIGNATURE_FLAG | CERT_STORE_BASE_CRL_FLAG;

static const CERT_CHAIN_POLICY_PARA _OE_DEFAULT_CERT_CHAIN_POLICY = {
    .cbSize = sizeof(CERT_CHAIN_POLICY_PARA),
    .dwFlags = 0};

static const CERT_STRONG_SIGN_PARA _OE_DEFAULT_SIGN_PARAMS = {
    .cbSize = sizeof(CERT_STRONG_SIGN_PARA),
    .dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE,
    .pszOID = szOID_CERT_STRONG_SIGN_OS_1};

static const CERT_CHAIN_PARA _OE_DEFAULT_CERT_CHAIN_PARAMS = {
    .cbSize = sizeof(CERT_CHAIN_PARA),
    .RequestedUsage = {0},
    .RequestedIssuancePolicy = {0},
    .dwUrlRetrievalTimeout = 0,
    .fCheckRevocationFreshnessTime = FALSE,
    .dwRevocationFreshnessTime = 0,
    .pftCacheResync = NULL,
    .pStrongSignPara = &_OE_DEFAULT_SIGN_PARAMS,
    .dwStrongSignFlags = 0};

static const DWORD _OE_DEFAULT_CERT_CHAIN_FLAGS =
    CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_REVOCATION_CHECK_CHAIN;

typedef struct _cert
{
    uint64_t magic;
    PCCERT_CONTEXT cert;
} cert_t;

OE_STATIC_ASSERT(sizeof(cert_t) <= sizeof(oe_cert_t));

OE_INLINE void _cert_init(cert_t* impl, PCCERT_CONTEXT cert_context)
{
    impl->magic = OE_CERT_MAGIC;
    impl->cert = cert_context;
}

OE_INLINE bool _cert_is_valid(const cert_t* impl)
{
    return impl && (impl->magic == OE_CERT_MAGIC) && impl->cert;
}

OE_INLINE void _cert_destroy(cert_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->cert = NULL;
    }
}

typedef struct _cert_chain
{
    uint64_t magic;
    PCCERT_CHAIN_CONTEXT cert_chain;
    HCERTSTORE cert_store;
} cert_chain_t;

OE_STATIC_ASSERT(sizeof(cert_chain_t) <= sizeof(oe_cert_chain_t));

static void _cert_chain_init(
    cert_chain_t* impl,
    PCCERT_CHAIN_CONTEXT cert_chain,
    HCERTSTORE cert_store)
{
    impl->magic = OE_CERT_CHAIN_MAGIC;
    impl->cert_chain = cert_chain;
    impl->cert_store = cert_store;
}

static bool _cert_chain_is_valid(const cert_chain_t* impl)
{
    return impl && (impl->magic == OE_CERT_CHAIN_MAGIC) && impl->cert_chain &&
           impl->cert_store;
}

static void _cert_chain_destroy(cert_chain_t* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->cert_chain = NULL;
        impl->cert_store = NULL;
    }
}

static void _free_urls_array(char*** urls, DWORD* urls_count)
{
    if (urls)
    {
        if (*urls && *urls_count)
        {
            for (DWORD i = 0; i < *urls_count; i++)
            {
                if ((*urls)[i])
                    free((*urls)[i]);
            }
            *urls_count = 0;
            free(*urls);
        }
        *urls = NULL;
    }
}

/* Find the last certificate in the cert chain and then verify that it's a
 * self-signed certificate (a root certificate). */
static PCCERT_CONTEXT _find_root_cert(PCCERT_CHAIN_CONTEXT cert_chain)
{
    PCCERT_CONTEXT root_cert = NULL;
    DWORD cert_count = 0;
    if (cert_chain && cert_chain->cChain > 0 &&
        cert_chain->rgpChain[0]->cElement > 0)
    {
        cert_count = cert_chain->rgpChain[0]->cElement;

        /* Get the last certificate in the list */
        if (!(root_cert = cert_chain->rgpChain[0]
                              ->rgpElement[cert_count - 1]
                              ->pCertContext))
        {
            return NULL;
        }

        /* If the last certificate is not self-signed, then fail */
        {
            PCERT_NAME_BLOB subject = &root_cert->pCertInfo->Subject;
            PCERT_NAME_BLOB issuer = &root_cert->pCertInfo->Issuer;

            /* This assumes that the issuer & subject fields in the same cert
             * share a canonical encoding, like the mbedTLS impl does */
            if (!subject || !issuer || subject->cbData != issuer->cbData ||
                memcmp(subject->pbData, issuer->pbData, subject->cbData) != 0)
                return NULL;
        }
    }

    /* Return the root certificate */
    return root_cert;
}

/* Caller is expected to call CryptCloseStore on output cert_store */
static oe_result_t _bcrypt_load_cert_store_pem(
    const void* pem_data,
    size_t pem_data_size,
    HCERTSTORE* cert_store)
{
    oe_result_t result = OE_UNEXPECTED;
    CRYPT_DATA_BLOB der_blob = {0};
    char* pem_cert = NULL;
    size_t pem_cert_size = 0;
    size_t remaining_size = pem_data_size;
    const void* read_pos = pem_data;
    bool found_certs = false;
    HCERTSTORE load_cert_store =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);

    if (!load_cert_store)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "CertOpenStore failed, err=%#x\n", GetLastError());

    while (remaining_size >
           OE_PEM_BEGIN_CERTIFICATE_LEN + OE_PEM_END_CERTIFICATE_LEN)
    {
        oe_result_t find_result = oe_get_next_pem_cert(
            &read_pos, &remaining_size, &pem_cert, &pem_cert_size);
        if (find_result == OE_NOT_FOUND)
            break;
        else if (find_result != OE_OK)
            OE_RAISE(find_result);

        OE_CHECK(oe_bcrypt_pem_to_der(
            (const uint8_t*)pem_cert,
            pem_cert_size,
            &der_blob.pbData,
            &der_blob.cbData));
        free(pem_cert);
        pem_cert = NULL;

        if (!CertAddEncodedCertificateToStore(
                load_cert_store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der_blob.pbData,
                der_blob.cbData,
                CERT_STORE_ADD_REPLACE_EXISTING,
                NULL))
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertAddEncodedCertificateToStore failed, err=%#x\n",
                GetLastError());
        }

        found_certs = true;

        free(der_blob.pbData);
        der_blob.pbData = NULL;
        der_blob.cbData = 0;
    }

    if (!found_certs)
        OE_RAISE(
            OE_INVALID_PARAMETER,
            "No certs could be loaded from provided PEM.\n",
            NULL);

    *cert_store = load_cert_store;
    load_cert_store = NULL;
    result = OE_OK;

done:
    if (load_cert_store)
        CertCloseStore(load_cert_store, 0);

    if (pem_cert)
        free(pem_cert);

    if (der_blob.pbData)
    {
        free(der_blob.pbData);
        der_blob.pbData = NULL;
        der_blob.cbData = 0;
    }

    return result;
}

/* Verify each certificate in the chain against its predecessor. */
static oe_result_t _bcrypt_get_cert_chain(
    PCCERT_CONTEXT cert_context,
    HCERTSTORE trusted_store,
    size_t expected_chain_length,
    PCCERT_CHAIN_CONTEXT* cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    PCCERT_CHAIN_CONTEXT found_chain = NULL;

    /* CertGetCertificateChain can increment the refcount on cert_context
     * by >1 due to CERT_CHAIN_CACHE_END_CERT. Do not force close the store,
     * which will destroy the cached cert and corrupt future cert chaining
     * calls.
     */
    if (!CertGetCertificateChain(
            NULL, /* use the default engine */
            cert_context,
            NULL, /* use the default time */
            trusted_store,
            (PCERT_CHAIN_PARA)&_OE_DEFAULT_CERT_CHAIN_PARAMS,
            _OE_DEFAULT_CERT_CHAIN_FLAGS,
            NULL, /* reserved */
            &found_chain))
    {
        DWORD err = GetLastError();
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "CertGetCertificateChain failed, err=%#x\n", err);
    }

    if (found_chain && found_chain->cChain > 0 &&
        (expected_chain_length == _OE_CERT_CHAIN_LENGTH_ANY ||
         found_chain->rgpChain[0]->cElement == expected_chain_length))
    {
        *cert_chain = found_chain;
        found_chain = NULL;
        result = OE_OK;
    }
    else
        result = OE_NOT_FOUND;

done:
    if (found_chain)
        CertFreeCertificateChain(found_chain);

    return result;
}

static oe_result_t _bcrypt_check_revocation(
    PCCERT_CONTEXT cert,
    PCERT_CHAIN_ELEMENT* cert_issuers,
    DWORD cert_issuers_count,
    HCERTSTORE cert_store)
{
    oe_result_t result = OE_UNEXPECTED;

    bool is_validated = false;
    DWORD flags = _OE_DEFAULT_GET_CRL_FLAGS;
    PCCRL_CONTEXT prev_crl = NULL;
    PCCRL_CONTEXT crl = CertGetCRLFromStore(
        cert_store, cert_issuers[0]->pCertContext, prev_crl, &flags);

    /* NOTE: This implementation does not support delta CRLs.
     * It will need to collate all CRLs per issuer with the base
     * and then pass them into a single CertVerifyCRLRevocation check. */
    while (crl && (flags & CERT_STORE_BASE_CRL_FLAG))
    {
        flags = _OE_DEFAULT_GET_CRL_FLAGS;
        crl = CertGetCRLFromStore(
            cert_store, cert_issuers[0]->pCertContext, crl, &flags);
    }

    if (crl)
    {
        if (flags & CERT_STORE_SIGNATURE_FLAG)
            OE_RAISE_MSG(
                OE_VERIFY_FAILED,
                "CertGetCRLFromStore: CRL failed signature validation.\n",
                NULL);

        if (flags & CERT_STORE_TIME_VALIDITY_FLAG)
            OE_RAISE_MSG(
                OE_VERIFY_CRL_EXPIRED,
                "CertGetCRLFromStore: CRL out of time validity.\n",
                NULL);

        if (CertIsValidCRLForCertificate(cert, crl, 0, NULL))
        {
            if (!CertVerifyCRLRevocation(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    cert->pCertInfo,
                    1,
                    (PCRL_INFO*)&crl->pCrlInfo))
            {
                OE_RAISE(OE_VERIFY_REVOKED);
            }

            is_validated = true;
        }
    }
    else
    {
        /* For parity with OpenSSL implementation, we require that a CRL
         * is provided for each issuer in the chain. */
        DWORD error = GetLastError();
        if (error == (DWORD)CRYPT_E_NOT_FOUND)
            OE_RAISE(OE_VERIFY_CRL_MISSING);
        else
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertGetCRLFromStore failed, err=%#x\n",
                error);
    }

    /* Given an existing validation, it's also possible (albeit irrgular) for a
     * higher CA to revoke the cert still. */
    if (cert_issuers_count > 1)
    {
        oe_result_t parent_result = _bcrypt_check_revocation(
            cert, &cert_issuers[1], cert_issuers_count - 1, cert_store);

        /* The parent issuer not having an applicable CRL for the cert is not
         * necessarily an error, since is_validated may already be true. */
        if (parent_result == OE_OK)
            is_validated = true;
        else if (parent_result != OE_VERIFY_CRL_MISSING)
            OE_RAISE(parent_result);
    }

    /* Check if any of the CRLs were applicable to the cert */
    if (!is_validated)
        OE_RAISE_MSG(
            OE_VERIFY_CRL_MISSING,
            "No CRLs found were applicable to the cert.\n",
            NULL);

    result = OE_OK;

done:
    if (crl)
        CertFreeCRLContext(crl);

    return result;
}

static oe_result_t _bcrypt_verify_cert_chain(
    HCERTSTORE cert_store,
    PCCERT_CHAIN_CONTEXT cert_chain)
{
    oe_result_t result = OE_UNEXPECTED;
    CERT_CHAIN_POLICY_STATUS policy_status = {
        .cbSize = sizeof(CERT_CHAIN_POLICY_STATUS)};
    bool have_crls = false;

    if (!_find_root_cert(cert_chain))
        OE_RAISE_MSG(OE_VERIFY_FAILED, "No root certificate found\n", NULL);

    /* NOTE: This only validates the cert chain structure for basic
     * constraints such as path length. Cert chains generated via
     * CertGetCertificateChain should already be valid in that regard.
     *
     * Ideally, this should try to run CERT_CHAIN_POLICY_AUTHENTICODE,
     * which will also check cert_chain->TrustStatus for signature and
     * revocation errors, but given the current parameterization, it is
     * flagging CERT_TRUST_IS_NOT_SIGNATURE_VALID which seems to be flowing
     * from CERT_TRUST_IS_UNTRUSTED_ROOT, which is expected given that the
     * attestation cert trust is independent of the Windows root trust
     */
    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_BASIC_CONSTRAINTS,
            cert_chain,
            (PCERT_CHAIN_POLICY_PARA)&_OE_DEFAULT_CERT_CHAIN_POLICY,
            &policy_status))
    {
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CertVerifyCertificateChainPolicy could not check policy\n",
            NULL);
    }

    /* Success on CertVerifyCertificateChainPolicy does not indicate
     * successful validation, that's reflected in the policy_status */
    if (policy_status.dwError != ERROR_SUCCESS)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "CertVerifyCertificateChainPolicy failed, err=%#x\n",
            policy_status.dwError);

    /* Determine if certificate trust store provided contains any CRLs */
    if (cert_store)
    {
        PCCRL_CONTEXT found_crl = CertEnumCRLsInStore(cert_store, NULL);
        if (found_crl)
        {
            CertFreeCRLContext(found_crl);
            have_crls = true;
        }
    }

    /* Explicitly walk the chain and validate the signatures */
    DWORD cert_count = cert_chain->rgpChain[0]->cElement;
    for (DWORD i = 0; i < cert_count; i++)
    {
        bool isRootCert = (cert_count == i + 1);
        PCERT_CONTEXT cert =
            (PCERT_CONTEXT)cert_chain->rgpChain[0]->rgpElement[i]->pCertContext;
        PCERT_CHAIN_ELEMENT* issuer_element = NULL;
        PCERT_CONTEXT issuer = cert;
        if (!isRootCert)
        {
            issuer_element = &cert_chain->rgpChain[0]->rgpElement[i + 1];
            issuer = (PCERT_CONTEXT)((*issuer_element)->pCertContext);
        }

        BOOL success = CryptVerifyCertificateSignatureEx(
            0,
            X509_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
            cert,
            CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
            issuer,
            CRYPT_VERIFY_CERT_SIGN_DISABLE_MD2_MD4_FLAG,
            NULL);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptVerifyCertificateSignatureEx failed, err=%#x\n",
                GetLastError());

        /* Perform CRL validations if CRLs were provided */
        if (have_crls && !isRootCert)
        {
            OE_CHECK(_bcrypt_check_revocation(
                cert, issuer_element, cert_count - 1 - i, cert_store));
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _bcrypt_get_public_key_from_cert(
    const oe_cert_t* cert,
    BCRYPT_KEY_HANDLE* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get public key */
    status = CryptImportPublicKeyInfoEx2(
        X509_ASN_ENCODING,
        &impl->cert->pCertInfo->SubjectPublicKeyInfo,
        0,
        NULL,
        public_key);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptImportPublicKeyInfoEx2 failed, err=%#x\n",
            status);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _bcrypt_get_key_algorithm(
    BCRYPT_KEY_HANDLE key,
    PWSTR* alg_name,
    ULONG* alg_name_size)
{
    oe_result_t result = OE_UNEXPECTED;
    PUCHAR buffer = NULL;
    ULONG buffer_size = 0;
    NTSTATUS status;

    if (!key || !alg_name || !alg_name_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    status =
        BCryptGetProperty(key, BCRYPT_ALGORITHM_NAME, NULL, 0, &buffer_size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptGetProperty failed, err=%#x\n", status);

    buffer = malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    status = BCryptGetProperty(
        key, BCRYPT_ALGORITHM_NAME, buffer, buffer_size, &buffer_size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptGetProperty failed, err=%#x\n", status);

    *alg_name = (PWSTR)buffer;
    *alg_name_size = buffer_size;
    buffer = NULL;
    result = OE_OK;

done:
    if (buffer)
        free(buffer);

    return result;
}

/* Caller is expected to invoke _free_urls_array on output urls */
static oe_result_t _bcrypt_get_distribution_point_urls(
    PCRL_DIST_POINTS_INFO dist_points_info,
    char*** urls,
    DWORD* urls_count,
    size_t* urls_total_length)
{
    oe_result_t result = OE_UNEXPECTED;
    DWORD found_urls_count = 0;
    size_t found_urls_total_length = 0;
    char** found_urls =
        (char**)malloc(dist_points_info->cDistPoint * sizeof(char*));

    if (!found_urls)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Walk the CRL_DIST_POINTS_INFO for only valid URL distribution points */
    for (DWORD i = 0; i < dist_points_info->cDistPoint; i++)
    {
        CRL_DIST_POINT cdp = dist_points_info->rgDistPoint[i];

        /* Ignore unspecified distribution points (CRL_DIST_POINT_NO_NAME) */
        if (cdp.DistPointName.dwDistPointNameChoice != CRL_DIST_POINT_FULL_NAME)
            continue;

        CERT_ALT_NAME_INFO alt_name_info = cdp.DistPointName.FullName;
        for (DWORD j = 0; j < alt_name_info.cAltEntry; j++)
        {
            /* Ignore all other name formats other than URL */
            if (alt_name_info.rgAltEntry->dwAltNameChoice != CERT_ALT_NAME_URL)
                continue;

            /* RFC5280 requires that IRI must be mapped to URI for
             * inclusion in x509 certs, so we reject conversions that
             * result in string expansion.
             *
             * Note: This implementation expects that the URIs are
             * normalized per RFC3987 already. */

            /* Include size for null-terminator */
            size_t url_length = wcslen(alt_name_info.rgAltEntry[j].pwszURL) + 1;
            found_urls[found_urls_count] = (char*)malloc(url_length);
            if (!found_urls[found_urls_count])
                OE_RAISE(OE_OUT_OF_MEMORY);

            {
                size_t write_length = 0;
                errno_t err = wcstombs_s(
                    &write_length,
                    found_urls[found_urls_count],
                    url_length,
                    alt_name_info.rgAltEntry[j].pwszURL,
                    url_length - 1);

                if (err)
                    OE_RAISE_MSG(
                        OE_UNEXPECTED, "wcstombs_s failed with err:%d\n", err);

                /* Resulting write_length should include null-terminator */
                if (write_length != url_length)
                    OE_RAISE_MSG(
                        OE_INVALID_PARAMETER,
                        "Unsupported conversion of IRI to URI:%S\n",
                        alt_name_info.rgAltEntry[j].pwszURL);

                found_urls_count++;
                OE_CHECK(oe_safe_add_u64(
                    found_urls_total_length,
                    url_length,
                    &found_urls_total_length));
            }
        }
    }

    /* Check that at least one valid URL was found */
    if (found_urls_count == 0)
        OE_RAISE(OE_NOT_FOUND);

    *urls_total_length = found_urls_total_length;
    *urls_count = found_urls_count;
    *urls = found_urls;
    found_urls = NULL;
    result = OE_OK;

done:
    _free_urls_array(&found_urls, &found_urls_count);

    return result;
}

/*
**==============================================================================
**
** Public functions
**
**==============================================================================
*/

/* Used by tests/crypto_crls_cert_chains */
oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    BYTE* der_data = NULL;
    DWORD der_data_size = 0;

    /* Zero-initialize the implementation */
    if (impl)
        memset(impl, 0, sizeof(cert_t));

    OE_CHECK(oe_bcrypt_pem_to_der(
        pem_data, pem_data_size, &der_data, &der_data_size));
    OE_CHECK(oe_cert_read_der(cert, der_data, der_data_size));

    result = OE_OK;

done:
    if (der_data)
        free(der_data);

    return result;
}

oe_result_t oe_cert_read_der(
    oe_cert_t* cert,
    const void* der_data,
    size_t der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;
    PCCERT_CONTEXT cert_context = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        memset(impl, 0, sizeof(cert_t));

    if (der_data_size > MAXDWORD)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create the CERT_CONTEXT from DER data */
    cert_context = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        der_data,
        (DWORD)der_data_size);

    if (!cert_context)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CertCreateCertificateContext failed, err=%#x\n",
            GetLastError());

    /* Initialize the wrapper cert_context structure */
    _cert_init(impl, cert_context);
    cert_context = NULL;
    result = OE_OK;

done:
    if (cert_context)
        CertFreeCertificateContext(cert_context);

    return result;
}

oe_result_t oe_cert_free(oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;

    /* Check parameters */
    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the certificate */
    CertFreeCertificateContext(impl->cert);
    _cert_destroy(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_read_pem(
    oe_cert_chain_t* chain,
    const void* pem_data,
    size_t pem_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;
    PCCERT_CHAIN_CONTEXT cert_chain = NULL;
    HCERTSTORE cert_store = NULL;
    uint32_t cert_count = 0;
    PCCERT_CONTEXT cert_context = NULL;

    /* Zero-initialize the implementation */
    if (impl)
        memset(impl, 0, sizeof(cert_chain_t));

    /* Check parameters */
    if (!pem_data || !pem_data_size || !chain)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the certs from the PEM into a cert store */
    OE_CHECK(_bcrypt_load_cert_store_pem(pem_data, pem_data_size, &cert_store));

    /* Count the number of unique certs in the resulting cert store */
    while (
        (cert_context = CertEnumCertificatesInStore(cert_store, cert_context)))
        cert_count++;

    if (cert_count == 0)
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER, "No certs read from pem_data\n", NULL);

    /* Without assuming an ordering of certificates added to the cert store,
     * try constructing a cert chain with each cert in the store as the leaf
     * cert until a cert chain is found that uses all certs in the store and
     * terminates in a self-signed (root) certificate.
     */
    while (
        (cert_context = CertEnumCertificatesInStore(cert_store, cert_context)))
    {
        oe_result_t find_result = _bcrypt_get_cert_chain(
            cert_context, cert_store, cert_count, &cert_chain);

        if (find_result == OE_OK)
        {
            break;
        }
        else if (find_result != OE_NOT_FOUND)
        {
            OE_RAISE(find_result);
        }
    }

    if (!cert_chain)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED,
            "pem_data does not contain a valid cert chain\n",
            NULL);

    /* Sanity check the structure of the resulting cert chain */
    OE_CHECK(_bcrypt_verify_cert_chain(NULL, cert_chain));

    _cert_chain_init(impl, cert_chain, cert_store);
    cert_chain = NULL;
    cert_store = NULL;
    result = OE_OK;

done:
    if (cert_context)
        CertFreeCertificateContext(cert_context);

    if (cert_chain)
        CertFreeCertificateChain(cert_chain);

    if (cert_store)
        CertCloseStore(cert_store, 0);

    return result;
}

oe_result_t oe_cert_chain_free(oe_cert_chain_t* chain)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_chain_t* impl = (cert_chain_t*)chain;

    /* Check the parameter */
    if (!_cert_chain_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    CertFreeCertificateChain(impl->cert_chain);

    if (impl->cert_store)
        CertCloseStore(impl->cert_store, 0);

    /* Clear the implementation */
    _cert_chain_destroy(impl);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_verify(
    oe_cert_t* cert,
    oe_cert_chain_t* chain,
    const oe_crl_t* const* crls,
    size_t num_crls)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* cert_impl = (cert_t*)cert;
    cert_chain_t* chain_impl = (cert_chain_t*)chain;
    DWORD chain_count = 0;
    HCERTSTORE cert_store = NULL;
    PCCERT_CHAIN_CONTEXT cert_chain = NULL;

    /* Check for invalid cert parameter */
    if (!_cert_is_valid(cert_impl))
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid cert parameter", NULL);

    /* Check for invalid chain parameter */
    if (chain_impl && !_cert_chain_is_valid(chain_impl))
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "Invalid chain parameter", NULL);

    /* Create a store for the verification */
    cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!cert_store)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "Failed to allocate X509 store", NULL);

    /* Add certs in chain to cert store, if any */
    if (chain)
    {
        if (chain_impl->cert_chain->cChain > 0 &&
            chain_impl->cert_chain->rgpChain[0])
        {
            chain_count = chain_impl->cert_chain->rgpChain[0]->cElement;
        }
        else
        {
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Invalid chain parameter contains no certs",
                NULL);
        }

        for (DWORD i = 0; i < chain_count; i++)
        {
            if (!CertAddCertificateContextToStore(
                    cert_store,
                    chain_impl->cert_chain->rgpChain[0]
                        ->rgpElement[i]
                        ->pCertContext,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    NULL))
            {
                OE_RAISE_MSG(
                    OE_CRYPTO_ERROR,
                    "CertAddCertificateContextToStore failed, err=%#x\n",
                    GetLastError());
            }
        }
    }

    /* Add CRLs to cert store */
    for (size_t j = 0; j < num_crls; j++)
    {
        PCCRL_CONTEXT crl_context;
        OE_CHECK(oe_crl_get_context(crls[j], &crl_context));

        if (!CertAddCRLContextToStore(
                cert_store, crl_context, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CertAddCRLContextToStore failed, err=%#x\n",
                GetLastError());
        }
    }

    result = _bcrypt_get_cert_chain(
        cert_impl->cert, cert_store, _OE_CERT_CHAIN_LENGTH_ANY, &cert_chain);

    if (result == OE_NOT_FOUND)
        OE_RAISE_MSG(
            OE_VERIFY_FAILED, "No valid cert chain could be found\n", NULL);

    OE_CHECK(_bcrypt_verify_cert_chain(cert_store, cert_chain));

    result = OE_OK;

done:
    if (cert_chain)
        CertFreeCertificateChain(cert_chain);

    if (cert_store)
        CertCloseStore(cert_store, 0);

    return result;
}

oe_result_t oe_get_crl_distribution_points(
    const oe_cert_t* cert,
    char*** urls,
    size_t* num_urls,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;

    PCRL_DIST_POINTS_INFO dist_points_info = NULL;
    DWORD dist_points_info_size = 0;
    PCERT_EXTENSION cdp_ext = NULL;

    char** found_urls = NULL;
    DWORD found_urls_count = 0;
    size_t found_urls_total_length = 0;

    /* Clear output args for all error pathways */
    if (urls)
        *urls = NULL;

    if (num_urls)
        *num_urls = 0;

    if (!cert || !urls || !num_urls || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is not aligned properly to hold an array of pointers */
    if (oe_align_pointer(buffer, sizeof(void*)) != buffer)
        OE_RAISE(OE_BAD_ALIGNMENT);

    cdp_ext = CertFindExtension(
        szOID_CRL_DIST_POINTS,
        impl->cert->pCertInfo->cExtension,
        impl->cert->pCertInfo->rgExtension);
    if (!cdp_ext)
        OE_RAISE_MSG(
            OE_NOT_FOUND,
            "No valid CRL Distribution Point could be found\n",
            NULL);

    {
        BOOL success = CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_CRL_DIST_POINTS,
            cdp_ext->Value.pbData,
            cdp_ext->Value.cbData,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &dist_points_info,
            &dist_points_info_size);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptDecodeObjectEx failed (err=%#x)\n",
                GetLastError());
    }

    /* Read all the distribution points that specify URL endpoints */
    OE_CHECK(_bcrypt_get_distribution_point_urls(
        dist_points_info,
        &found_urls,
        &found_urls_count,
        &found_urls_total_length));

    {
        /* Calculate the required buffer_size */
        size_t found_urls_size = found_urls_count * sizeof(char*);
        size_t required_size = 0;
        OE_CHECK(oe_safe_add_u64(
            found_urls_size, found_urls_total_length, &required_size));

        if (*buffer_size < required_size)
        {
            *buffer_size = required_size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy the URLs array and pack the URL strings into buffer */
        if (buffer)
        {
            char* offset = (char*)buffer + found_urls_size;
            size_t remaining_bytes = found_urls_total_length;
            char** urls_array = (char**)buffer;
            for (DWORD k = 0; k < found_urls_count; k++)
            {
                size_t url_size = strlen(found_urls[k]) + 1;

                urls_array[k] = offset;
                OE_CHECK(oe_memcpy_s(
                    offset, remaining_bytes, found_urls[k], url_size));

                offset += url_size;
                remaining_bytes -= url_size;
                assert(remaining_bytes >= 0);
            }
            assert(remaining_bytes == 0);

            *buffer_size = required_size;
            *num_urls = found_urls_count;
            *urls = urls_array;
        }
    }

    result = OE_OK;

done:
    _free_urls_array(&found_urls, &found_urls_count);

    if (dist_points_info)
        LocalFree(dist_points_info);

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_cert_get_rsa_public_key(
    const oe_cert_t* cert,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    PWSTR key_alg_name = NULL;
    ULONG key_alg_name_size;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_rsa_public_key_t));

    /* Reject invalid parameters */
    if (!cert || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_bcrypt_get_public_key_from_cert(cert, &key_handle));

    /* Check if RSA key */
    result = _bcrypt_get_key_algorithm(
        key_handle, &key_alg_name, &key_alg_name_size);
    if (result != OE_OK)
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    if (wcsncmp(
            key_alg_name,
            BCRYPT_RSA_ALGORITHM,
            _countof(BCRYPT_RSA_ALGORITHM) - 1) != 0)
    {
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);
    }

    /* Initialize the RSA public key */
    oe_rsa_public_key_init(public_key, key_handle);
    key_handle = NULL;

    result = OE_OK;

done:
    if (key_handle)
        BCryptDestroyKey(key_handle);

    if (key_alg_name)
        free(key_alg_name);

    return result;
}

oe_result_t oe_cert_get_ec_public_key(
    const oe_cert_t* cert,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    PWSTR key_alg_name = NULL;
    ULONG key_alg_name_size;

    /* Clear public key for all error pathways */
    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!cert || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_bcrypt_get_public_key_from_cert(cert, &key_handle));

    /* Check if EC key */
    result = _bcrypt_get_key_algorithm(
        key_handle, &key_alg_name, &key_alg_name_size);
    if (result != OE_OK)
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    if (wcsncmp(
            key_alg_name,
            BCRYPT_ECDSA_ALGORITHM,
            _countof(BCRYPT_ECDSA_ALGORITHM) - 1) != 0 &&
        wcsncmp(
            key_alg_name,
            BCRYPT_ECDH_ALGORITHM,
            _countof(BCRYPT_ECDH_ALGORITHM) - 1) != 0)
    {
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);
    }

    /* Initialize the EC public key */
    oe_ec_public_key_init(public_key, key_handle);
    key_handle = NULL;

    result = OE_OK;

done:
    if (key_handle)
        BCryptDestroyKey(key_handle);

    if (key_alg_name)
        free(key_alg_name);

    return result;
}

/* Used by tests/crypto/ec_tests|rsa_tests */
oe_result_t oe_cert_chain_get_length(
    const oe_cert_chain_t* chain,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;

    /* Clear the length (for failed return case) */
    if (length)
        *length = 0;

    /* Reject invalid parameters */
    if (!_cert_chain_is_valid(impl) || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the number of certificates in the chain */
    if (impl->cert_chain->cChain == 0 || !impl->cert_chain->rgpChain ||
        impl->cert_chain->rgpChain[0]->cElement == 0)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "No certs found in oe_cert_chain_t impl\n", NULL);

    *length = (size_t)impl->cert_chain->rgpChain[0]->cElement;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_get_cert(
    const oe_cert_chain_t* chain,
    size_t index,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_chain_t* impl = (const cert_chain_t*)chain;
    size_t length;
    PCCERT_CONTEXT found_cert = NULL;

    /* Clear the output certificate for all error pathways */
    if (cert)
        memset(cert, 0, sizeof(oe_cert_t));
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the length of the certificate chain, also validates chain arg */
    OE_CHECK(oe_cert_chain_get_length(chain, &length));

    /* Check for out of bounds */
    if (index >= length)
        OE_RAISE(OE_OUT_OF_BOUNDS);

    /* Check for overflow as int because that is the OpenSSL limit */
    if (index >= OE_INT_MAX)
        OE_RAISE(OE_INTEGER_OVERFLOW);

    found_cert = CertDuplicateCertificateContext(
        impl->cert_chain->rgpChain[0]->rgpElement[index]->pCertContext);

    if (!found_cert)
        OE_RAISE_MSG(OE_FAILURE, "Failed to get cert at valid index\n", NULL);

    _cert_init((cert_t*)cert, found_cert);
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_find_extension(
    const oe_cert_t* cert,
    const char* oid,
    uint8_t* data,
    size_t* data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    cert_t* impl = (cert_t*)cert;

    /* Reject invalid parameters */
    if (!_cert_is_valid(impl) || !oid || !data_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the certificate with this OID */
    PCERT_EXTENSION extension = CertFindExtension(
        oid,
        impl->cert->pCertInfo->cExtension,
        impl->cert->pCertInfo->rgExtension);

    if (!extension)
        OE_RAISE(OE_NOT_FOUND);

    /* If the caller's buffer is too small, raise error */
    if (extension->Value.cbData > *data_size)
    {
        *data_size = extension->Value.cbData;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    if (data)
    {
        OE_CHECK(oe_memcpy_s(
            data,
            *data_size,
            extension->Value.pbData,
            extension->Value.cbData));
        *data_size = extension->Value.cbData;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_get_validity_dates(
    const oe_cert_t* cert,
    oe_datetime_t* not_before,
    oe_datetime_t* not_after)
{
    oe_result_t result = OE_UNEXPECTED;
    const cert_t* impl = (const cert_t*)cert;

    if (!_cert_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (not_before)
    {
        memset(not_before, 0, sizeof(oe_datetime_t));

        OE_CHECK(oe_util_filetime_to_oe_datetime(
            &impl->cert->pCertInfo->NotBefore, not_before));
    }

    if (not_after)
    {
        memset(not_after, 0, sizeof(oe_datetime_t));

        OE_CHECK(oe_util_filetime_to_oe_datetime(
            &impl->cert->pCertInfo->NotAfter, not_after));
    }

    result = OE_OK;

done:

    return result;
}
