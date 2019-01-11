/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <time.h>

#include <string.h>

#include <openenclave/enclave.h>

#include <errno.h>

#ifdef OE_USE_OPTEE
#include <rand_optee.h>
#endif
#ifndef USE_OPENSSL
# ifdef OE_USE_SGX
#  define WOLFSSL_SGX
# endif
# define WOLFCRYPT_ONLY
# define NO_WOLFSSL_DIR
# define NO_WRITEV
# define HAVE_ECC
# define WOLFSSL_KEY_GEN
#endif

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>

#ifdef USE_OPENSSL
#if defined(OE_USE_OPTEE) && defined(OPENSSL_SYSNAME_WIN32)
#  error "OPTEE is not compatible with OPENSSL_SYSNAME_WIN32, please update openssl/include/openssl/opensslconf.h"
#endif

#include <openssl/safestack.h>
#endif
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Returns 0 on success, errno on error. */
static oe_result_t GenerateKeyPairRsa(EVP_PKEY **pKeyPair)
{
    EVP_PKEY_CTX *genctx = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GenerateKeyPairRsa");

#if defined(OPENSSL_SYS_WINDOWS) || defined(OE_USE_OPTEE)
    RAND_screen();
#endif

    Tcps_GotoErrorIfTrue((genctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL, OE_FAILURE);
    Tcps_GotoErrorIfTrue(EVP_PKEY_keygen_init(genctx) <= 0, OE_FAILURE);

    // Set the key length to 1024 bits.
    Tcps_GotoErrorIfTrue(EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, 1024) <= 0, OE_FAILURE);

    // Generate the key.
    Tcps_GotoErrorIfTrue(EVP_PKEY_keygen(genctx, pKeyPair) <= 0, OE_FAILURE);

    EVP_PKEY_CTX_free(genctx);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (genctx != NULL) {
        EVP_PKEY_CTX_free(genctx);
    }

Tcps_FinishErrorHandling;
}

static oe_result_t GenerateKeyPairEc(EVP_PKEY **pKeyPair)
{
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY_CTX *paramctx = NULL;
    EVP_PKEY *params = NULL;

    Tcps_InitializeStatus(Tcps_Module_Helper_t, "GenerateKeyPairEc");

#if defined(OPENSSL_SYS_WINDOWS) || defined(OE_USE_OPTEE)
    RAND_screen();
#endif

    Tcps_GotoErrorIfTrue((paramctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL, OE_FAILURE);
    Tcps_GotoErrorIfTrue(!EVP_PKEY_paramgen_init(paramctx), OE_FAILURE);

    Tcps_GotoErrorIfTrue((!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramctx, NID_X9_62_prime256v1)), OE_FAILURE);
    Tcps_GotoErrorIfTrue (!EVP_PKEY_paramgen(paramctx, &params), OE_FAILURE);
    Tcps_GotoErrorIfTrue(params == NULL, OE_FAILURE);

    // Generate the key.
    Tcps_GotoErrorIfTrue((genctx = EVP_PKEY_CTX_new(params, NULL)) == NULL, OE_FAILURE);
    Tcps_GotoErrorIfTrue(!EVP_PKEY_keygen_init(genctx), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!EVP_PKEY_keygen(genctx, pKeyPair), OE_FAILURE);

    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_CTX_free(paramctx);

    Tcps_ReturnStatusCode;
    Tcps_BeginErrorHandling;

    if (genctx != NULL) {
        EVP_PKEY_CTX_free(genctx);
    }

    Tcps_FinishErrorHandling;
}

static int SavePkcs12(PKCS12* p12, const char* keyFileName)
{
    int err = 1;
    BIO *out = NULL;

    out = BIO_new(BIO_s_file());
    if (out == NULL) {
        goto Done;
    }
    if (BIO_write_filename(out, (char*)keyFileName) <= 0) {
        goto Done;
    }

    if (ASN1_item_i2d_bio(ASN1_ITEM_rptr(PKCS12), out, p12) <= 0) {
        goto Done;
    }

    err = 0;
Done:
    BIO_free_all(out);
    return err;
}

#define SERIAL_RAND_BITS 64
static int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
    BIGNUM *btmp;
    int ret = 0;
    if (b)
        btmp = b;
    else
        btmp = BN_new();

    if (!btmp)
        return 0;

    if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

error:

    if (!b) {
        BN_free(btmp);
    }

    return ret;
}

/*
* Add extension using V3 code: we can set the config file as NULL because we
* wont reference any other sections.
*/

static int add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
    * Issuer and subject certs: both the target since it is self signed, no
    * request and no CRL
    */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char*)value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

/* Returns 0 on success, errno on error. */
static oe_result_t
GenerateCertificate(
    const char* commonName,
    const char* certificateUri,
    const char* hostName,
    EVP_PKEY* keyPair,
    X509** pCertificate)
{
    int days = 365;
    int cleanupContext = 0;
    X509* x509ss = NULL;
    X509_REQ* req = NULL;
    EVP_PKEY* publicKey = NULL;
    X509_NAME* subjectName = NULL;
    char extBuffer[256];

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GenerateCertificate");

    // Create a certificate request.
    Tcps_GotoErrorIfTrue((req = X509_REQ_new()) == NULL, OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_REQ_set_version(req, 0L), OE_FAILURE);

    subjectName = X509_REQ_get_subject_name(req);
    Tcps_GotoErrorIfTrue(!X509_NAME_add_entry_by_NID(
        subjectName, 
        NID_commonName, 
        MBSTRING_ASC,
        (unsigned char*)commonName, 
        -1, -1, 0), OE_FAILURE);

    Tcps_GotoErrorIfTrue(!X509_REQ_set_pubkey(req, keyPair), OE_FAILURE);
    Tcps_GotoErrorIfTrue((publicKey = X509_REQ_get_pubkey(req)) == NULL, OE_FAILURE);

    // Create a certificate.
    x509ss = X509_new();
    Tcps_GotoErrorIfTrue(x509ss == NULL, OE_FAILURE);

    Tcps_GotoErrorIfTrue(!rand_serial(NULL, X509_get_serialNumber(x509ss)), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_set_issuer_name(x509ss, subjectName), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_gmtime_adj(X509_get_notBefore(x509ss), 0), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_time_adj_ex(X509_get_notAfter(x509ss), days, 0, NULL), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_set_subject_name(x509ss, subjectName), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_set_pubkey(x509ss, publicKey), OE_FAILURE);

    // Add subjectKeyIdentifier.
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_subject_key_identifier, "hash"), OE_FAILURE);

    // Add authorityKeyIdentifier.
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_authority_key_identifier, "keyid:always,issuer:always"), OE_FAILURE);

    // Add basicConstraints.
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_basic_constraints, "critical,CA:FALSE"), OE_FAILURE);

    // Add keyUsage.
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_key_usage, "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign"), OE_FAILURE);

    // Add extendedKeyUsage.
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_ext_key_usage, "critical,serverAuth,clientAuth"), OE_FAILURE);

    // Add subjectAltName.
    strcpy_s(extBuffer, sizeof(extBuffer), "URI:");
    strcat_s(extBuffer, sizeof(extBuffer), certificateUri);
    strcat_s(extBuffer, sizeof(extBuffer), ", DNS:");
    strcat_s(extBuffer, sizeof(extBuffer), hostName);
    Tcps_GotoErrorIfTrue(!add_ext(x509ss, NID_subject_alt_name, extBuffer), OE_FAILURE);

    // Sign the certificate.
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);
    cleanupContext = 1;
    EVP_PKEY_CTX *pkctx = NULL;
    const EVP_MD *digest = EVP_sha256();
    Tcps_GotoErrorIfTrue(!EVP_DigestSignInit(&mctx, &pkctx, digest, NULL, keyPair), OE_FAILURE);
    Tcps_GotoErrorIfTrue(!X509_sign_ctx(x509ss, &mctx), OE_FAILURE);

    *pCertificate = x509ss;

    EVP_MD_CTX_cleanup(&mctx);
    X509_REQ_free(req);
    EVP_PKEY_free(publicKey);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (cleanupContext) {
        EVP_MD_CTX_cleanup(&mctx);
    }

    if (req != NULL) {
        X509_REQ_free(req);
    }

    if (publicKey != NULL) {
        EVP_PKEY_free(publicKey);
    }

    if (x509ss != NULL) {
        X509_free(x509ss);
    }

Tcps_FinishErrorHandling;
}

static int SaveDerCertificate(X509* certificate, const char* certificateFileName)
{
    int err = 1;
    BIO *out = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "SaveDerCertificate");

    Tcps_Trace(Tcps_TraceLevelDebug, "cert path = %s\n", certificateFileName);

    Tcps_GotoErrorIfTrue((out = BIO_new(BIO_s_file())) == NULL, OE_FAILURE);
    Tcps_GotoErrorIfTrue(BIO_write_filename(out, (char*)certificateFileName) <= 0, OE_FAILURE);
    Tcps_GotoErrorIfTrue(!i2d_X509_bio(out, certificate), OE_FAILURE);

    // Compose manifest filename.
    Tcps_GotoErrorIfTrue(AppendFilenameToManifest(certificateFileName) != 0, OE_FAILURE);

    BIO_free_all(out);
    return 0;

Tcps_BeginErrorHandling;
    
    if (out != NULL) {
        BIO_free_all(out);
    }

    return 1;
}

static int GeneratePkcs12(PKCS12** pPkcs12, EVP_PKEY* keyPair, X509* certificate)
{
    STACK_OF(X509) *certs = NULL;
    int err = 1;
    const char* cpass = "";

    EVP_add_cipher(EVP_rc2_40_cbc());
    EVP_add_cipher(EVP_des_ede3_cbc());
    EVP_add_digest(EVP_sha1()); /* RSA with sha1 */
    
    certs = sk_X509_new_null();
    if (certs == NULL) {
        goto Done;
    }

    PKCS12* p12 = PKCS12_create((char*)cpass, NULL, keyPair, certificate, certs,
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
        NID_pbe_WithSHA1And40BitRC2_CBC,
        PKCS12_DEFAULT_ITER, -1, 0);
    if (p12 == NULL) {
        goto Done;
    }

    const char* mpass = "";
    if (PKCS12_set_mac(p12, mpass, -1, NULL, 0, PKCS12_DEFAULT_ITER, NULL) <= 0) {
        goto Done;
    }

    err = 0;
    *pPkcs12 = p12;

Done:
    if (certs != NULL) {
        sk_X509_pop_free(certs, X509_free);
    }
    return err;
}

oe_result_t
GenerateKeyAndCertificate(
    const char* commonName,
    const char* certificateUri,
    const char* hostName,
    const char* keyFileName,
    const char* certificateFileName, 
    const char* certificateFileNameExported,
    unsigned char isRsa)
{
    EVP_PKEY* keyPair = NULL;
    X509* certificate = NULL;
    PKCS12* p12 = NULL;
    FILE *fp = NULL;

Tcps_InitializeStatus(Tcps_Module_Helper_t, "GenerateKeyAndCertificate");

    Tcps_Trace(Tcps_TraceLevelDebug, "key           = %s\n", keyFileName);
    Tcps_Trace(Tcps_TraceLevelDebug, "cert          = %s\n", certificateFileName);
    Tcps_Trace(Tcps_TraceLevelDebug, "exported cert = %s\n", certificateFileNameExported);

    // See if a private key already exists.
    fp = fopen(keyFileName, "r");

    if (fp != NULL) {
        Tcps_Trace(Tcps_TraceLevelDebug, "GenerateKeyAndCertificate: key already exists\n");
        fclose(fp);
    } else {
        // Generate a private key.
        uStatus = isRsa ? GenerateKeyPairRsa(&keyPair) : GenerateKeyPairEc(&keyPair);
        Tcps_GotoErrorIfBad(uStatus);

        // Generate a self-signed X509 certificate.
        uStatus = GenerateCertificate(commonName, certificateUri, hostName, keyPair, &certificate);
        Tcps_GotoErrorIfBad(uStatus);

        // Save the certificate in DER format.
        Tcps_GotoErrorIfTrue(SaveDerCertificate(certificate, certificateFileName) != 0, OE_FAILURE);

        Tcps_GotoErrorIfTrue(GeneratePkcs12(&p12, keyPair, certificate) != 0, OE_FAILURE);
        Tcps_GotoErrorIfTrue(SavePkcs12(p12, keyFileName) != 0, OE_FAILURE);
    }

    Tcps_GotoErrorIfTrue(ExportPublicCertificate(certificateFileName, certificateFileNameExported) != 0, OE_FAILURE);

    X509_free(certificate);
    EVP_PKEY_free(keyPair);

Tcps_ReturnStatusCode;
Tcps_BeginErrorHandling;

    if (certificate != NULL) {
        X509_free(certificate);
    }

    if (keyPair != NULL) {
        EVP_PKEY_free(keyPair);
    }

Tcps_FinishErrorHandling;
}
