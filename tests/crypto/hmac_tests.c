// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/crypto/hmac.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "tests.h"

// Test compution of SHA256-HMAC over an ASCII string alphabet.
void TestHMAC(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    OE_SHA256 hash = {0};
    oe_hmac_sha256_context_t ctx = {0};
    oe_hmac_sha256_init(&ctx, ALPHABET_KEY, ALPHABET_KEY_SIZE);
    oe_hmac_sha256_update(&ctx, ALPHABET, strlen(ALPHABET));
    oe_hmac_sha256_final(&ctx, &hash);
    oe_hmac_sha256_free(&ctx);

    OE_TEST(memcmp(&hash, &ALPHABET_HMAC, sizeof(OE_SHA256)) == 0);

    printf("=== passed %s()\n", __FUNCTION__);
}
