// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "crypto.h"
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

static mbedtls_ctr_drbg_context m_ctr_drbg_contex;
static mbedtls_entropy_context m_entropy_context;
static mbedtls_pk_context m_pk_context;

/**
 * init_mbedtls initializes the crypto module.
 * mbedtls initialization. Please refer to mbedtls documentation for detailed
 * information about the functions used.
 */
bool init_mbedtls(void)
{
    bool ret = false;
    int res = -1;

    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);

    // Initialize entropy.
    res = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_contex, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed failed.");
        goto exit;
    }

    // Initialize RSA context.
    res = mbedtls_pk_setup(
        &m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    // Generate an ephemeral 2048-bit RSA key pair with
    // exponent 65537 for the enclave.
    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_pk_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        2048,
        65537);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_gen_key failed (%d)\n", res);
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("mbedtls initialized.");
exit:
    return ret;
}

/**
 * mbedtls cleanup during shutdown.
 */
void cleanup_mbedtls(void)
{
    mbedtls_pk_free(&m_pk_context);
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);

    TRACE_ENCLAVE("mbedtls cleaned up.");
}

// Compute the sha256 hash of given data.
int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}
