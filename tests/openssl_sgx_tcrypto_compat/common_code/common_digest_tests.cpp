// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include_openssl.h"

extern "C" int RAND_bytes(unsigned char* buf, int num);
extern "C" const char* SSL_alert_type_string_long(int);
extern "C" const char* SSL_alert_desc_string_long(int);

#include "openssl_schema.h"

#include "openssl_sgx_tcrypto_compat_t.h"

extern void my_strcpy(char* target, char* source);

bool first_loop = true;

void set_key(RSA* key, unsigned char* c)
{
    static unsigned char n[] =
        "\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
        "\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
        "\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
        "\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
        "\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
        "\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
        "\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
        "\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
        "\xCB";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
        "\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
        "\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
        "\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
        "\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
        "\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
        "\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
        "\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
        "\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
        "\xC1";

    static unsigned char p[] =
        "\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
        "\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
        "\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
        "\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
        "\x99";

    static unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
        "\x03";

    static unsigned char dmp1[] =
        "\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
        "\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
        "\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
        "\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    static unsigned char dmq1[] =
        "\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
        "\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
        "\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
        "\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";

    static unsigned char iqmp[] =
        "\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
        "\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
        "\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
        "\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
        "\xF7";

    static unsigned char ctext_ex[] =
        "\xb8\x24\x6b\x56\xa6\xed\x58\x81\xae\xb5\x85\xd9\xa2\x5b\x2a\xd7"
        "\x90\xc4\x17\xe0\x80\x68\x1b\xf1\xac\x2b\xc3\xde\xb6\x9d\x8b\xce"
        "\xf0\xc4\x36\x6f\xec\x40\x0a\xf0\x52\xa7\x2e\x9b\x0e\xff\xb5\xb3"
        "\xf2\xf1\x92\xdb\xea\xca\x03\xc1\x27\x40\x05\x71\x13\xbf\x1f\x06"
        "\x69\xac\x22\xe9\xf3\xa7\x85\x2e\x3c\x15\xd9\x13\xca\xb0\xb8\x86"
        "\x3a\x95\xc9\x92\x94\xce\x86\x74\x21\x49\x54\x61\x03\x46\xf4\xd4"
        "\x74\xb2\x6f\x7c\x48\xb4\x2e\xe6\x8e\x1f\x57\x2a\x1f\xc4\x02\x6a"
        "\xc4\x56\xb4\xf5\x9f\x7b\x62\x1e\xa1\xb9\xd8\x8f\x64\x20\x2f\xb1";

    key->n = BN_bin2bn(n, sizeof(n) - 1, key->n);
    key->e = BN_bin2bn(e, sizeof(e) - 1, key->e);
    key->d = BN_bin2bn(d, sizeof(d) - 1, key->d);
    key->p = BN_bin2bn(p, sizeof(p) - 1, key->p);
    key->q = BN_bin2bn(q, sizeof(q) - 1, key->q);
    key->dmp1 = BN_bin2bn(dmp1, sizeof(dmp1) - 1, key->dmp1);
    key->dmq1 = BN_bin2bn(dmq1, sizeof(dmq1) - 1, key->dmq1);
    key->iqmp = BN_bin2bn(iqmp, sizeof(iqmp) - 1, key->iqmp);
    memcpy(c, ctext_ex, sizeof(ctext_ex) - 1);
}

static void _cpy(char* p1, char* p2, size_t size)
{
    while (size)
    {
        *p1 = *p2;
        p1++;
        p2++;
        size--;
    }
}
static size_t _scpy(char* p1, const char* p2)
{
    size_t size = 0;

    while (*p2)
    {
        *p1 = *p2;
        p1++;
        p2++;
        size++;
    }
    *p1 = 0;
    return size + 1;
}
static int _update_sha1_test(openssl_api_param* p, int iter)
{
    SHA_CTX* ctx = (SHA_CTX*)p->p[0];
    unsigned char* data = (unsigned char*)p->p[1];
    size_t len = (size_t)p->p[2];
    int ret = SHA1_Init(ctx);

    if (1 != ret)
        return ret;

    for (int i = 0; i < iter; i++)
    {
        ret = SHA1_Update(ctx, data, len);
        if (1 != ret)
            break;
    }

    return ret;
}
static int _final_sha1_test(openssl_api_param* p, int iter)
{
    int ret;
    SHA_CTX* ctx = (SHA_CTX*)p->p[0];
    unsigned char* hash = (unsigned char*)p->p[3];

    ret = _update_sha1_test(p, iter);
    if (1 != ret)
        return ret;

    SHA1_Final(hash, ctx);
    return ret;
}
static int _update_sha256_test(openssl_api_param* p, int iter)
{
    SHA256_CTX* ctx = (SHA256_CTX*)p->p[0];
    unsigned char* data = (unsigned char*)p->p[1];
    size_t len = (size_t)p->p[2];
    int ret = SHA256_Init(ctx);

    if (1 != ret)
        return ret;

    for (int i = 0; i < iter; i++)
    {
        ret = SHA256_Update(ctx, data, len);
        if (1 != ret)
            break;
    }

    return ret;
}
static int _final_sha256_test(openssl_api_param* p, int iter)
{
    SHA256_CTX* ctx = (SHA256_CTX*)p->p[0];
    unsigned char* hash = (unsigned char*)p->p[3];
    int ret = _update_sha256_test(p, iter);

    if (1 != ret)
        return ret;

    SHA256_Final(hash, ctx);
    return ret;
}
#define _pkcs7_sign 0
#define _pkcs7_get_info 1
#define _pkcs7_verify 2
#define _x509_cert 3

static size_t serialize_ASN1_OBJECT(char* b, ASN1_OBJECT* obj)
{
    size_t size = 2 * sizeof(int);

    _cpy(b, (char*)&obj->nid, 2 * sizeof(int));
    _cpy(b + size, (char*)obj->data, (uint64_t)obj->length);
    size += (uint64_t)obj->length;
    _cpy(b + size, (char*)&obj->flags, sizeof(obj->flags));
    size += sizeof(obj->flags);
    return size;
}

static int _test_pkcs7_sign(openssl_api_param* p, int info)
{
    int ret = 0;
    EVP_PKEY* pkey = NULL;
    PKCS7* p7 = NULL;
    RSA* rsa = NULL;
    unsigned char ctext_ex[256];
    X509* x509 = NULL;
    BIO *in_bio = NULL, *out_bio = NULL;
    X509_NAME* name = NULL;
    BUF_MEM* y;

    // build the key
    pkey = EVP_PKEY_new();
    if (NULL == pkey)
        goto Exit;
    rsa = RSA_new();
    if (NULL == rsa)
        goto Exit;
    set_key(rsa, ctext_ex);
    ret = EVP_PKEY_assign_RSA(pkey, rsa);
    if (1 != ret)
        goto Exit;

    // build certificate
    x509 = X509_new();
    if (NULL == x509)
        goto Exit;
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(
        name, "C", MBSTRING_ASC, (unsigned char*)"IS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(
        name, "O", MBSTRING_ASC, (unsigned char*)"Intel corp", -1, -1, 0);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_sign(x509, pkey, EVP_md5());

    in_bio = BIO_new_mem_buf((void*)p->p[0], *(int*)&(p->p[1]));
    BIO_get_mem_ptr(in_bio, &y);
    y->length = (size_t)p->p[1];

    p7 = PKCS7_sign(x509, pkey, NULL, in_bio, 0);
    if (!p7)
    {
        ret = 0;
        goto Exit;
    }

    if (_pkcs7_get_info == info)
    {
        STACK_OF(PKCS7_SIGNER_INFO) * sinfos;
        PKCS7_SIGNER_INFO* sitmp;
        char* buffer = p->p[2];
        sinfos = PKCS7_get_signer_info(p7);
        if (!sinfos)
        {
            ret = 0;
        }

        // serialize partially the sinfos object in order to compare in checker
        int num = sk_PKCS7_SIGNER_INFO_num(sinfos);
        size_t total = 0;

        _cpy(buffer, (char*)&num, sizeof(num));
        total += sizeof(num);
        for (int i = 0; i < num; i++)
        {
            int x;
            sitmp = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
            x = sk_X509_ATTRIBUTE_num(sitmp->auth_attr);
            _cpy(buffer + total, (char*)&x, sizeof(num));
            total += sizeof(num);
            total += serialize_ASN1_OBJECT(
                buffer + total, sitmp->digest_alg->algorithm);
            total += serialize_ASN1_OBJECT(
                buffer + total, sitmp->digest_enc_alg->algorithm);
        }
    }
    else if (_pkcs7_sign == info)
    {
        size_t len;
        // write signature to buffer
        out_bio = BIO_new(BIO_s_mem());
        if (NULL == out_bio)
            goto Exit;
        ret = SMIME_write_PKCS7(out_bio, p7, in_bio, 0);
        if (1 != ret)
        {
            ret = 0;
            goto Exit;
        }

        BIO_get_mem_ptr(out_bio, &y);
        len = (size_t)p->p[1];
        _cpy(p->p[2], y->data, len);
    }
    else if (_pkcs7_verify == info)
    {
        STACK_OF(X509)* chain = NULL;

        chain = sk_X509_new_null();
        if (NULL == chain)
            goto Exit;
        sk_X509_push(chain, x509);
        ret = PKCS7_verify(p7, chain, NULL, NULL, NULL, PKCS7_NOVERIFY);
        sk_X509_pop(chain);
        sk_X509_free(chain);
    }
    else
    {
        X509_STORE* store = X509_STORE_new();
        if (NULL == store)
            goto Exit;
        X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());

        ret = X509_STORE_add_cert(lookup->store_ctx, x509);
        X509_STORE_free(store);
    }

Exit:

    if (in_bio)
        BIO_free(in_bio);
    if (out_bio)
        BIO_free(out_bio);
    if (x509)
        X509_free(x509);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (p7)
        PKCS7_free(p7);
    return ret;
}

static void Reset_EVP_MD_CTX(char* p)
{
    memset(p, 0, sizeof(EVP_MD_CTX));
}

const EVP_MD* some_EVP_sha(unsigned char c)
{
    c &= 0x3;

    switch (c)
    {
        case 0:
            return EVP_sha224();
        case 1:
            return EVP_sha256();
        case 2:
            return EVP_sha384();
        case 3:
            return EVP_sha512();
        default:
            break;
    }
    return NULL;
}

static int Create_EVP_MD_CTX()
{
    EVP_MD_CTX* ctx;
    ctx = EVP_MD_CTX_new();
    if (ctx)
    {
        EVP_MD_CTX_free(ctx);
        return 1;
    }
    else
    {
        return 0;
    }
}

int common_digest_tests(void* buf)
{
    openssl_api_param* p = (openssl_api_param*)buf;
    int ret = 1;

    OpenSSL_add_all_algorithms();

    try
    {
        switch (p->id)
        {
            case e_sha1_init:
            {
                SHA_CTX* ctx = (SHA_CTX*)p->p[0];
                ret = SHA1_Init(ctx);
            }
            break;
            case e_sha1_update:
                ret = _update_sha1_test(p, 1);
                break;
            case e_sha1_final:
                ret = _final_sha1_test(p, 1);
                break;
            case e_sha256_init:
            {
                SHA256_CTX* ctx = (SHA256_CTX*)p->p[0];
                ret = SHA256_Init(ctx);
                break;
            }
            case e_sha256_update:
                ret = _update_sha256_test(p, 1);
                break;
            case e_sha256_final:
                ret = _final_sha256_test(p, 1);
                break;
            case e_EVP_Sha256:
            {
                const EVP_MD* q = EVP_sha256();
                _cpy(p->p[0], (char*)q, sizeof(EVP_MD));
                break;
            }
            case e_EVP_Sha384:
            {
                const EVP_MD* q = EVP_sha384();
                _cpy(p->p[0], (char*)q, sizeof(EVP_MD));
                break;
            }
            case e_EVP_MD_CTX_init:
                Reset_EVP_MD_CTX(p->p[0]);
                break;
            case e_EVP_SignInit_ex:
            {
                const EVP_MD* emd;
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                unsigned char c = *((unsigned char*)emd_ctx);

                emd = some_EVP_sha(c);
                Reset_EVP_MD_CTX(p->p[0]);
                ret = EVP_SignInit_ex(emd_ctx, emd, NULL);
                _cpy(p->p[1], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                break;
            }
            case e_EVP_SignUpdate:
            {
                const EVP_MD* emd;
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                unsigned char* data = (unsigned char*)(p->p[1]);
                size_t len = (size_t)p->p[2];
                unsigned char c = *((unsigned char*)emd_ctx);

                emd = some_EVP_sha(c);

                Reset_EVP_MD_CTX(p->p[0]);
                ret = EVP_SignInit_ex(emd_ctx, emd, NULL);
                if (1 != ret)
                    break;

                ret = EVP_SignUpdate(emd_ctx, data, len);
                _cpy(p->p[3], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                break;
            }
            case e_EVP_SignFinal:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                const EVP_MD* emd;
                EVP_PKEY* pkey;
                RSA* rsa;
                unsigned char ctext_ex[256];
                unsigned char* sig;
                unsigned char c = *((unsigned char*)emd_ctx);

                emd = some_EVP_sha(c);

                Reset_EVP_MD_CTX((char*)emd_ctx);
                ret = EVP_SignInit_ex(emd_ctx, emd, NULL);
                if (1 != ret)
                    break;

                ret = EVP_SignUpdate(emd_ctx, "hello ", 6);
                if (1 != ret)
                    break;

                pkey = EVP_PKEY_new();
                if (NULL == pkey)
                    goto Exit;
                rsa = RSA_new();
                if (NULL == rsa)
                    goto Exit;
                set_key(rsa, ctext_ex);

                ret = EVP_PKEY_assign_RSA(pkey, rsa);
                if (1 != ret)
                    break;

                sig = (unsigned char*)malloc((uint32_t)EVP_PKEY_size(pkey));
                ret = EVP_SignFinal(emd_ctx, sig, (unsigned int*)p->p[2], pkey);
                _cpy(p->p[4], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                free(sig);
                EVP_PKEY_free(pkey);
                break;
            }
            case e_EVP_VerifyInit_ex:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                const EVP_MD* md;
                unsigned char c = *((unsigned char*)emd_ctx);

                md = some_EVP_sha(c);
                Reset_EVP_MD_CTX((char*)emd_ctx);
                ret = EVP_VerifyInit_ex(emd_ctx, md, NULL);
                _cpy(p->p[1], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                break;
            }
            case e_EVP_VerifyUpdate:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                const EVP_MD* md;
                unsigned char c = *((unsigned char*)emd_ctx);

                md = some_EVP_sha(c);
                Reset_EVP_MD_CTX((char*)emd_ctx);
                ret = EVP_VerifyInit_ex(emd_ctx, md, NULL);
                if (1 != ret)
                    break;

                ret = EVP_VerifyUpdate(
                    emd_ctx, (void*)p->p[1], *(unsigned int*)&(p->p[2]));
                _cpy(p->p[3], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                break;
            }
            case e_EVP_VerifyFinal:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                const EVP_MD* md;
                EVP_PKEY* pkey;
                RSA* rsa;
                unsigned char ctext_ex[256];
                unsigned char c = *((unsigned char*)emd_ctx);

                md = some_EVP_sha(c);
                Reset_EVP_MD_CTX((char*)emd_ctx);
                ret = EVP_VerifyInit_ex(emd_ctx, md, NULL);
                if (1 != ret)
                    break;

                ret = EVP_VerifyUpdate(emd_ctx, (void*)"Hello buffer", 12);
                if (1 != ret)
                    break;

                pkey = EVP_PKEY_new();
                if (NULL == pkey)
                    goto Exit;
                rsa = RSA_new();
                if (NULL == rsa)
                    goto Exit;
                set_key(rsa, ctext_ex);

                ret = EVP_PKEY_assign_RSA(pkey, rsa);
                if (1 != ret)
                    break;

                if (_ELLEPH < EVP_PKEY_size(pkey))
                {
                    ret = -1;
                    break;
                }

                ret = EVP_VerifyFinal(
                    emd_ctx, (const unsigned char*)p->p[1], _ELLEPH, pkey);
                _cpy(p->p[4], (char*)emd_ctx->digest, sizeof(*emd_ctx->digest));
                EVP_PKEY_free(pkey);
                goto Exit;
            }

            case e_PKCS7_sign:
                ret = _test_pkcs7_sign(p, _pkcs7_sign);
                break;
            case e_PKCS7_get_signer_info:
                ret = _test_pkcs7_sign(p, _pkcs7_get_info);
                break;
            case e_PKCS7_verify:
                ret = _test_pkcs7_sign(p, _pkcs7_verify);
                break;
            case e_EVP_MD_CTX_create:
            case e_EVP_MD_CTX_destroy:
            {
                ret = Create_EVP_MD_CTX();
                break;
            }
            case e_SSLeay_version:
            {
                int type = *((int*)p->p[0]) % 10;
                const char* version = SSLeay_version(type);
                if (SSLEAY_VERSION_NUMBER == type || SSLEAY_PLATFORM == type)
                    _scpy(p->p[1], version);
                break;
            }
            case e_X509_STORE_add_cert:
                ret = _test_pkcs7_sign(p, _x509_cert);
                break;
            case e_EVP_EncodeInit:
            {
                EVP_ENCODE_CTX* ctx = (EVP_ENCODE_CTX*)p->p[0];
                EVP_EncodeInit(ctx);
                ret = 1;
            }
            break;
            case e_EVP_EncodeUpdate:
            {
                EVP_ENCODE_CTX* ctx = (EVP_ENCODE_CTX*)p->p[0];
                EVP_EncodeInit(ctx);
                unsigned char* out = (unsigned char*)p->p[1];
                int outl = *(int*)&(p->p[2]);
                int inl = (int)(outl * 0.7);
                const unsigned char* in = (const unsigned char*)p->p[3];
                EVP_EncodeUpdate(ctx, out, &outl, in, inl);
                ret = outl;
            }
            break;
            case e_EVP_DecodeInit:
            {
                EVP_ENCODE_CTX* ctx = (EVP_ENCODE_CTX*)p->p[0];
                EVP_DecodeInit(ctx);
                ret = 1;
            }
            break;
            case e_EVP_DecodeUpdate:
            {
                EVP_ENCODE_CTX ctx;
                EVP_EncodeInit(&ctx);
                unsigned char* out = (unsigned char*)p->p[1];
                int outl = *(int*)&(p->p[2]);
                int inl = (int)(outl * 0.7);
                unsigned char* in = (unsigned char*)p->p[3];
                unsigned char* tmpout =
                    (unsigned char*)OPENSSL_malloc((uint32_t)outl);
                if (!tmpout)
                {
                    ret = -1;
                    break;
                }
                EVP_EncodeUpdate(&ctx, tmpout, &outl, in, inl);
                EVP_ENCODE_CTX* ctx1 = (EVP_ENCODE_CTX*)p->p[0];
                EVP_DecodeInit(ctx1);
                ret = EVP_DecodeUpdate(ctx1, out, &outl, tmpout, outl);
                OPENSSL_free(tmpout);
            }
            break;
            case e_EVP_DecodeFinal:
            {
                BIO* my_bio = BIO_new(BIO_s_mem());
                if (NULL == my_bio)
                    goto Exit;
                unsigned char* buf = (unsigned char*)p->p[1];
                int buflen = *(int*)&(p->p[2]);
                buflen = (int)(buflen * 0.7);

                int ret = PEM_write_bio(
                    my_bio, "my test", "", (unsigned char*)buf, buflen);
                char* name;
                char* header;
                unsigned char* data;
                long datalen;
                ret = PEM_read_bio(my_bio, &name, &header, &data, &datalen);
                if (memcmp(data, buf, (uint32_t)buflen))
                    ret = 0; // Error
                else
                    ret = 1; // OK
                BIO_free_all(my_bio);
                if (name)
                    OPENSSL_free(name);
                if (header)
                    OPENSSL_free(header);
                if (data)
                    OPENSSL_free(data);
            }
            break;
            case e_EVP_DigestInit_ex:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                const EVP_MD* md = EVP_sha1();

                Reset_EVP_MD_CTX(p->p[0]);
                ret = EVP_DigestInit_ex(emd_ctx, md, NULL);
            }
            break;
            case e_EVP_DigestUpdate:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                unsigned char* data = (unsigned char*)(p->p[1]);
                size_t len = (size_t)p->p[2];
                const EVP_MD* md = EVP_sha1();

                Reset_EVP_MD_CTX(p->p[0]);
                ret = EVP_DigestInit_ex(emd_ctx, md, NULL);
                if (1 != ret)
                    break;

                ret = EVP_DigestUpdate(emd_ctx, data, len);
            }
            break;
            case e_EVP_DigestFinal_ex:
            {
                EVP_MD_CTX* emd_ctx = (EVP_MD_CTX*)p->p[0];
                unsigned char* md_value = (unsigned char*)(p->p[1]);
                unsigned int md_len = *(unsigned int*)&(p->p[2]);
                const EVP_MD* md = EVP_sha1();

                Reset_EVP_MD_CTX(p->p[0]);
                ret = EVP_DigestInit_ex(emd_ctx, md, NULL);
                if (1 != ret)
                    break;

                ret = EVP_DigestFinal_ex(emd_ctx, md_value, &md_len);
            }
            break;
            default:
                throw "unexpected api";
                break;
        };
    }
    catch (char* msg)
    {
        ret = 0;
    }

Exit:

    EVP_cleanup();

    return ret;
}
