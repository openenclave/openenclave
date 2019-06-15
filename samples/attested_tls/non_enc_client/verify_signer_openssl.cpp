// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>
#include "../common/common.h"
#include "../common/tls_server_enc_pubkey.h"

// Need the following block for supporting both OPENSSL 1.0 and 1.1
#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed for compatibility with ssl1.1 */
static void RSA_get0_key(
    const RSA* r,
    const BIGNUM** n,
    const BIGNUM** e,
    const BIGNUM** d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}
#endif

// Compute the sha256 hash of given data.
static int Sha256(const uint8_t* data, size_t data_size, uint8_t* sha256)
{
    int ret = 0;
    SHA256_CTX ctx;

    ret = SHA256_Init(&ctx);
    if (!ret)
        goto done;

    ret = SHA256_Update(&ctx, data, data_size);
    if (!ret)
        goto done;

    ret = SHA256_Final(sha256, &ctx);
    if (!ret)
        goto done;

    ret = 0;
done:
    return ret;
}

bool verify_mrsigner_openssl(
    char* pem_key_buffer,
    size_t pem_key_buffer_len,
    uint8_t* expected_signer,
    size_t expected_signer_size)
{
    unsigned char* modulus = NULL;
    const BIGNUM* modulus_bn = NULL;
    char* modulus_raw = NULL;
    size_t modulus_size = 0;
    int res = 0;
    bool ret = false;
    unsigned char* calculated_signer = NULL;
    BIO* bufio = NULL;
    RSA* rsa = NULL;
    int len = 0;
    EVP_PKEY* evp_key = NULL;
    int tmp_size = 0;

    printf(TLS_CLIENT "Verify connecting server's identity\n");
    calculated_signer = (unsigned char*)malloc(expected_signer_size);
    if (calculated_signer == NULL)
    {
        printf(TLS_CLIENT "Out of memory\n");
        goto done;
    }
    // The following printf are for debugging
    // printf(TLS_CLIENT "expected_signer_size=[%lu]\n", expected_signer_size);
    // printf(TLS_CLIENT "public key buffer size[%lu]\n", pem_key_buffer_len);
    // printf(TLS_CLIENT "public key\n[%s]\n", pem_key_buffer);

    // convert a public key in buffer format into a rsa key
    bufio = BIO_new(BIO_s_mem());
    len = BIO_write(bufio, pem_key_buffer, pem_key_buffer_len);
    if (len != pem_key_buffer_len)
    {
        printf(TLS_CLIENT "BIO_write error\n");
        goto done;
    }
    //
    // export rsa key, read its modulus
    //
    evp_key = PEM_read_bio_PUBKEY(bufio, NULL, NULL, NULL);
    if (evp_key == NULL)
    {
        printf(TLS_CLIENT "PEM_read_bio_PUBKEY failed\n");
        goto done;
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL)
    {
        printf(TLS_CLIENT "EVP_PKEY_get1_RSA failed\n");
        goto done;
    }
    // retrieves the length of RSA modulus in bytes
    modulus_size = RSA_size(rsa);
    printf(TLS_CLIENT "modulus_size=%zu\n", modulus_size);
    RSA_get0_key(rsa, &modulus_bn, NULL, NULL);
    if (modulus_bn == NULL)
    {
        printf(TLS_CLIENT "RSA_get0_key modulus_bn failed\n");
        goto done;
    }

    if (modulus_size != BN_num_bytes(modulus_bn))
    {
        printf(TLS_CLIENT "mismatched modulus size\n");
        goto done;
    }

    modulus = (unsigned char*)malloc(modulus_size);
    if (modulus == NULL)
    {
        printf(TLS_CLIENT "Out of memory\n");
        goto done;
    }

    tmp_size = BN_bn2bin(modulus_bn, modulus);
    if (tmp_size != modulus_size)
        goto done;

    // MRSIGNER stores a SHA256 in little endian implemented natively on x86
    // Reverse the modulus and compute sha256 on it.
    //
    // Calculate the MRSIGNER value which is the SHA256 hash of the
    // little endian representation of the public key modulus.
    for (size_t i = 0; i < modulus_size / 2; i++)
    {
        uint8_t tmp = modulus[i];
        modulus[i] = modulus[modulus_size - 1 - i];
        modulus[modulus_size - 1 - i] = tmp;
    }

    if (Sha256((const uint8_t*)modulus, modulus_size, calculated_signer) != 0)
        goto done;

    // validate against
    if (memcmp(calculated_signer, expected_signer, expected_signer_size) != 0)
    {
        printf("mrsigner is not equal!\n");
        for (int i = 0; i < expected_signer_size; i++)
        {
            printf(
                "0x%x - 0x%x\n",
                (uint8_t)expected_signer[i],
                (uint8_t)calculated_signer[i]);
        }
        goto done;
    }
    printf("signer id (MRSIGNER) was successfully validated\n");
    ret = true;
done:
    free(calculated_signer);
    free(modulus);
    BIO_free(bufio);
    RSA_free(rsa);
    EVP_PKEY_free(evp_key);

    return ret;
}
