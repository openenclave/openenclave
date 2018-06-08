// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/bits/sha.h>
#include <openenclave/bits/tests.h>
#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "sha_tests.h"

// Test computation of SHA-256 hash over an ASCII alphabet string.
void TestSHA()
{
    printf("=== begin %s()\n", __FUNCTION__);

    OE_SHA256 hash;
    oe_sha256__context_t ctx;
    oe_sha256__init(&ctx);
    oe_sha256__update(&ctx, ALPHABET, strlen(ALPHABET));
    oe_sha256__final(&ctx, &hash);
    OE_TEST(memcmp(&hash, &ALPHABET_HASH, sizeof(OE_SHA256)) == 0);

    printf("=== passed %s()\n", __FUNCTION__);
}
