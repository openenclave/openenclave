// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef __OPENSSL_SCHEMA_H__
#define __OPENSSL_SCHEMA_H__

#define OPENSSL_MAX_PARAMETER_COUNT 9
#define MAX_VAR_LEN_VALUES 2

// flags describing parameter attributes
#define _VALID 0x0000
#define _IN 1
#define _OUT 2
#define _FIXLEN 3  // size of parameter is fixed
#define _VARLEN 4  // "" not fixed
#define _RAND 5    // should be random
#define _LEN 6     // the length of the random
#define _VARLEN2 7 // "" not fixed
#define _LEN2 8    // the length of the random

// flags describing compare function required
#define _CMP_EVP_CIPHER_CTX 1
#define _CMP_EVP_CIPHER 2
#define _CMP_EVP_MD_CTX 3
#define _CMP_EVP_MD 4
#define _CMP_RAND 5
#define _CMP_HMAC_CTX 6

// set for a few flags
#define S_FIXLEN_IN ((1 << _VALID) | (1 << _IN) | (1 << _FIXLEN))
#define S_FIXLEN_O ((1 << _VALID) | (1 << _FIXLEN) | (1 << _OUT))
#define S_FIXLEN_IO ((1 << _VALID) | (1 << _IN) | (1 << _FIXLEN) | (1 << _OUT))
// NOTE - S_VARLEN uses the length randomized for the parameter defined as S_LEN
#define S_VARLEN_I ((1 << _VALID) | (1 << _IN) | (1 << _VARLEN))
#define S_VARLEN_O ((1 << _VALID) | (1 << _OUT) | (1 << _VARLEN))
#define S_LEN ((1 << _VALID) | (1 << _LEN))
// NOTE - S_VARLEN2 uses the length randomized for the parameter defined as
// S_LEN2
#define S_VARLEN2_I ((1 << _VALID) | (1 << _IN) | (1 << _VARLEN2))
#define S_VARLEN2_O ((1 << _VALID) | (1 << _OUT) | (1 << _VARLEN2))
#define S_LEN2 ((1 << _VALID) | (1 << _LEN2))

#define S_RAND (1 << _RAND)

#define S_CMP_EVP_CIPHER_CTX ((uint64_t)_CMP_EVP_CIPHER_CTX << 56)
#define S_CMP_EVP_MD_CTX ((uint64_t)_CMP_EVP_MD_CTX << 56)
#define S_CMP_EVP_MD ((uint64_t)_CMP_EVP_MD << 56)
#define S_CMP_RAND ((uint64_t)_CMP_RAND << 56)
#define S_CMP_HMAC_CTX ((uint64_t)_CMP_HMAC_CTX << 56)

#define SSL_VALID(_t) (_t & (1 << _VALID))
#define SSL_FIXLEN(_t) (_t & (1 << _FIXLEN))
#define SSL_VARLEN(_t) (_t & (1 << _VARLEN))
#define SSL_IN(_t) (_t & (1 << _IN))
#define SSL_LEN(_t) (_t & (1 << _LEN))
#define SSL_VARLEN2(_t) (_t & (1 << _VARLEN2))
#define SSL_LEN2(_t) (_t & (1 << _LEN2))
// check for both types of variable length
#define SSL_VARLEN_X(_t) ((_t & (1 << _VARLEN)) || (_t & (1 << _VARLEN2)))
#define SSL_WHICH_VARLEN(_t) (SSL_VARLEN(_t) ? 0 : 1)
#define SSL_LEN_X(_t) ((_t & (1 << _LEN)) || (_t & (1 << _LEN2)))
#define SSL_WHICH_LEN(_t) (SSL_LEN(_t) ? 0 : 1)

#define _ELLEPH 1024

typedef enum
{
    // SHA1
    e_sha1_init = 0,
    e_sha1_update,
    e_sha1_final,
    // SHA256
    e_sha256_init,
    e_sha256_update,
    e_sha256_final,
    // EVP
    e_EVP_Sha256,
    e_EVP_Sha384,
    e_EVP_MD_CTX_init,
    e_EVP_SignInit_ex,
    e_EVP_SignUpdate,
    e_EVP_SignFinal,
    e_EVP_VerifyInit_ex,
    e_EVP_VerifyUpdate,
    e_EVP_VerifyFinal,
    e_PKCS7_sign,
    e_PKCS7_sign_add_signer,
    e_PKCS7_get_signer_info,
    e_PKCS7_verify,
    e_EVP_MD_CTX_create,
    e_EVP_MD_CTX_destroy,
    e_Rand_bytes,
    e_EVP_EncodeInit,
    e_EVP_EncodeUpdate,
    e_EVP_EncodeFinal,
    e_EVP_DecodeInit,
    e_EVP_DecodeUpdate,
    e_EVP_DecodeFinal,

    e_EVP_DigestInit_ex,
    e_EVP_DigestUpdate,
    e_EVP_DigestFinal_ex,

    e_SSLeay_version,
    e_SSL_alert_type_string_l,
    e_SSL_alert_desc_string_l,
    e_CRYPTO_THREADID_set_numeric,
    e_X509_STORE_add_cert,

    e_RSA_generate_key_ex = 100,
    e_RSA_generate_key,
    e_RSA_public_encrypt,
    e_RSA_public_decrypt,
    e_RSA_private_encrypt,
    e_RSA_private_decrypt,

    e_EVP_CipherInit_ex = 120,
    e_EVP_CipherUpdate,
    e_EVP_CipherFinal_ex,
    e_HMAC,

    e_EVP_PKEY_assign,

    e_X509_REQ_new,
    e_X509_REQ_sign,
    e_X509_REQ_free,
    e_X509_REQ_set_pubkey,
    e_X509_free,
    e_PEM_write_bio_X509_REQ,
    e_PEM_read_bio_X509,
    e_X509_NAME_add_entry_by_txt,
    e_X509_VERIFY_PARAM,
    e_X509_ADD_CRL,
    e_X509_CRL_VERIFY,
    e_d2i_X509_CRL,
    e_X509_VERIFY_CRL,

    e_SSL_CTX_new = 200,
    e_SSL_write = 210,
    e_SSL_read = 211,
    e_SSL_done = 299, // dummy api to release the ssl connection object

    e_EC_Key = 300,
    e_OBJ_txt2nid,
    e_i2d_PrivateKey,

    e_Lock = 400,
    e_readers,
    e_return_values,
} openssl_api_id;

#define MAX_API_NAME 40
typedef struct openssl_schema
{
    char api_name[MAX_API_NAME];
    openssl_api_id id;
    int parameter_count;
    size_t length[OPENSSL_MAX_PARAMETER_COUNT];
    uint64_t type[OPENSSL_MAX_PARAMETER_COUNT];
} t_openssl_schema;

struct openssl_api_param
{
    openssl_api_id id;
    char* p[OPENSSL_MAX_PARAMETER_COUNT];
};

#endif
