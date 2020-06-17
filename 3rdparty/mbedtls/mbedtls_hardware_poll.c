// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>
#include <string.h>
#include "mbedtls/include/mbedtls/platform.h"
#include "mbedtls/include/mbedtls/sha512.h"

/* Per https://software.intel.com/en-us/articles/intel-digital-random-number
 * -generator-drng-software-implementation-guide, reading 512 x 128-bit values
 * causes RDRAND to reseed */
#define RDRAND_RESEED_SIZE_BYTES 8192

#define SHA512_HASH_LENGTH_BYTES 64

int mbedtls_hardware_poll(void*, unsigned char*, size_t, size_t*);

static void _fill_buffer(
    uint8_t* source,
    size_t source_size,
    uint8_t** target,
    size_t* target_size)
{
    size_t copy_size =
        (*target_size > source_size) ? source_size : *target_size;
    memcpy(*target, source, copy_size);
    *target += copy_size;
    *target_size -= copy_size;
}

static int _get_seed_from_rdrand(uint8_t** seed, size_t* seed_size)
{
    int ret = -1;
    uint8_t* rdrand_seed = NULL;
    uint8_t* rdrand_bytes = NULL;
    oe_entropy_kind_t kind = OE_ENTROPY_KIND_NONE;

    /* Per Intel's DRNG software implementation guide we try to obtain an
     * equivalent amount of entropy by condensing several reseed windows of
     * RDRAND into a single value.
     *
     * The DRBG that underlies RDRAND is limited to 128-bit security, so the
     * seed for each consecutive RDRAND_RESEED_SIZE_BYTES of data can be
     * recovered with 2^128 rounds of work. In general, to achieve N*128 bits
     * of security, we need a buffer of (N+1)*RDRAND_RESEED_SIZE_BYTES bytes.
     * To get to 256-bit security, similar to RDSEED for 32-bytes, we use N=3.
     *
     * Note that we hash this down to a 512-bit (64-byte) value via SHA-512 to
     * avoid loss of entropy that would otherwise occur in hash collisions when
     * mapping 256-bits of unique values into a 256-bit hash space.
     */
    size_t rdrand_bytes_size = RDRAND_RESEED_SIZE_BYTES * 3;
    rdrand_bytes = (uint8_t*)mbedtls_calloc(1, rdrand_bytes_size);
    if (!rdrand_bytes)
        goto done;

    if (oe_get_entropy(rdrand_bytes, rdrand_bytes_size, &kind) != OE_OK ||
        kind != OE_ENTROPY_KIND_RDRAND)
        goto done;

    /* Hash the bytes down to a single 64-byte seed value */
    rdrand_seed = (uint8_t*)mbedtls_calloc(1, SHA512_HASH_LENGTH_BYTES);
    if (!rdrand_seed)
        goto done;

    if (mbedtls_sha512_ret(rdrand_bytes, rdrand_bytes_size, rdrand_seed, 0) !=
        0)
        goto done;

    *seed_size = SHA512_HASH_LENGTH_BYTES;
    *seed = rdrand_seed;
    rdrand_seed = NULL;
    ret = 0;

done:
    if (rdrand_bytes)
    {
        mbedtls_free(rdrand_bytes);
        rdrand_bytes = NULL;
    }
    if (rdrand_seed)
    {
        mbedtls_free(rdrand_seed);
        rdrand_seed = NULL;
    }
    return ret;
}

/*
 * MBEDTLS links this function definition when MBEDTLS_ENTROPY_HARDWARE_ALT
 * is defined in the MBEDTLS config.h file. This is the sole source of entropy
 * for MBEDTLS. All other MBEDTLS entropy sources are disabled since they don't
 * work within enclaves.
 */
int mbedtls_hardware_poll(
    void* data,
    unsigned char* output,
    size_t len,
    size_t* olen)
{
    int ret = -1;
    oe_entropy_kind_t kind = OE_ENTROPY_KIND_NONE;
    OE_UNUSED(data);

    if (olen)
        *olen = 0;

    if (oe_get_entropy(output, len, &kind) != OE_OK)
        goto done;

    if (kind == OE_ENTROPY_KIND_RDSEED || kind == OE_ENTROPY_KIND_OPTEE)
    {
        /* According to Intel's DRNG software implementation guide, RDSEED
         * produces values that are already passed through a conditioner that
         * hashes pairs of 256-bit raw entropy samples via AES-CBC-MAC, so no
         * further work needs to be done.
         *
         * For OPTEE TEE_GenerateRandom, the actual predictive resistance of
         * underlying implementation may vary, so this simply takes the value
         * provided as is. */
    }
    else if (kind == OE_ENTROPY_KIND_RDRAND)
    {
        /* If RDSEED is not supported, fallback to using RDRAND to obtain a
         * seed for entropy. */
        unsigned char* p = (unsigned char*)output;
        size_t bytes_left = len;
        while (bytes_left > 0)
        {
            uint8_t* seed_bytes = NULL;
            size_t seed_size = 0;

            if (_get_seed_from_rdrand(&seed_bytes, &seed_size) != OE_OK)
                goto done;

            _fill_buffer(seed_bytes, seed_size, &p, &bytes_left);
            mbedtls_free(seed_bytes);
        }
    }
    else
    {
        goto done;
    }

    if (olen)
        *olen = len;

    ret = 0;

done:
    return ret;
}
