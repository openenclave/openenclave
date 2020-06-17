// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/crypto/sha.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "tests.h"

// Test computation of SHA-256 hash over an ASCII alphabet string.
void TestSHA(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    {
        OE_SHA256 hash = {0};
        oe_sha256_context_t ctx = {0};
        oe_sha256_init(&ctx);
        oe_sha256_update(&ctx, ALPHABET, strlen(ALPHABET));
        oe_sha256_final(&ctx, &hash);
        OE_TEST(memcmp(&hash, &ALPHABET_HASH, sizeof(OE_SHA256)) == 0);
    }

    {
        OE_SHA256 hash = {0};
        OE_TEST(oe_sha256(ALPHABET, strlen(ALPHABET), &hash) == OE_OK);
        OE_TEST(memcmp(&hash, &ALPHABET_HASH, sizeof(OE_SHA256)) == 0);
    }

    printf("=== passed %s()\n", __FUNCTION__);
}
