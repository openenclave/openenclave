// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define MEM_MIN_CAP 1
#include <openenclave/internal/mem.h>
#include <openenclave/internal/random.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

const char* ALPHABET = "abcdefghijklmnopqrstuvwxyz";

/* Hash of ALPHABET string above */
OE_SHA256 ALPHABET_HASH = {{
    0x71, 0xc4, 0x80, 0xdf, 0x93, 0xd6, 0xae, 0x2f, 0x1e, 0xfa, 0xd1,
    0x44, 0x7c, 0x66, 0xc9, 0x52, 0x5e, 0x31, 0x62, 0x18, 0xcf, 0x51,
    0xfc, 0x8d, 0x9e, 0xd8, 0x32, 0xf2, 0xda, 0xf1, 0x8b, 0x73,
}};

#define N 64
#define M 19

void TestSHA(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    OE_SHA256 hash = {0};
    oe_sha256_context_t ctx = {0};
    oe_sha256_init(&ctx);
    oe_sha256_update(&ctx, ALPHABET, strlen(ALPHABET));
    oe_sha256_final(&ctx, &hash);
    OE_TEST(memcmp(&hash, &ALPHABET_HASH, sizeof(OE_SHA256)) == 0);

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRandom(void)
{
    printf("=== begin %s()\n", __FUNCTION__);

    uint8_t buf[N][M];

    memset(buf, 0, sizeof(buf));

    for (size_t i = 0; i < N; i++)
    {
        /* Generate a random sequence */
        OE_TEST(oe_random(buf[i], M * sizeof(uint8_t)) == OE_OK);

        /* Be sure buffer is not filled with same character */
        {
            size_t m;
            uint8_t c = buf[i][0];

            for (m = 1; m < M && buf[i][m] == c; m++)
                ;

            OE_TEST(m != M);
        }

        /* Check whether duplicate of one of the previous calls */
        for (size_t j = 0; j < i; j++)
        {
            OE_TEST(memcmp(buf[j], buf[i], M * sizeof(uint8_t)) != 0);
        }
    }

    printf("=== passed %s()\n", __FUNCTION__);
}

void TestMem(mem_t* m)
{
    OE_TEST(mem_cpy(m, "hijk", 4) == 0);
    OE_TEST(mem_size(m) == 4);
    OE_TEST(mem_cap(m) >= 4);
    OE_TEST(memcmp(mem_ptr(m), "hijk", 4) == 0);

    OE_TEST(mem_append(m, "lmnop", 5) == 0);
    OE_TEST(mem_size(m) == 9);
    OE_TEST(mem_cap(m) >= 9);
    OE_TEST(memcmp(mem_ptr(m), "hijklmnop", 9) == 0);

    OE_TEST(mem_insert(m, 0, "abcdefg", 7) == 0);
    OE_TEST(mem_size(m) == 16);
    OE_TEST(mem_cap(m) >= 16);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnop", 16) == 0);

    OE_TEST(mem_append(m, "qrstuv", 6) == 0);
    OE_TEST(mem_size(m) == 22);
    OE_TEST(mem_cap(m) >= 22);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    OE_TEST(mem_append(m, "wxyz", 4) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_remove(m, 22, 4) == 0);
    OE_TEST(mem_size(m) == 22);
    OE_TEST(mem_cap(m) >= 22);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    OE_TEST(mem_append(m, "wxyz", 4) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_remove(m, 0, 7) == 0);
    OE_TEST(mem_size(m) == 19);
    OE_TEST(mem_cap(m) >= 19);
    OE_TEST(memcmp(mem_ptr(m), "hijklmnopqrstuvwxyz", 19) == 0);

    OE_TEST(mem_prepend(m, "abcdefg", 7) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_prepend(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 27);
    OE_TEST(mem_cap(m) >= 27);
    OE_TEST(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz", 27) == 0);

    OE_TEST(mem_append(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 28);
    OE_TEST(mem_cap(m) >= 28);
    OE_TEST(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz\0", 28) == 0);

    OE_TEST(mem_remove(m, 0, 1) == 0);
    OE_TEST(mem_remove(m, mem_size(m) - 1, 1) == 0);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_resize(m, 7) == 0);
    OE_TEST(mem_size(m) == 7);
    OE_TEST(mem_cap(m) >= 7);
    OE_TEST(memcmp(mem_ptr(m), "abcdefg", 7) == 0);

    OE_TEST(mem_append(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 8);
    OE_TEST(memcmp(mem_ptr(m), "abcdefg\0", 8) == 0);

    printf("=== passed TestMem()\n");
}

int main(int argc, const char* argv[])
{
    /* TestMem dynamic */
    {
        mem_t m;
        OE_TEST(mem_dynamic(&m, NULL, 0, 0) == 0);
        OE_TEST(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    /* TestMem static */
    {
        unsigned char buf[32];
        mem_t m;
        OE_TEST(mem_static(&m, buf, sizeof(buf)) == 0);
        OE_TEST(mem_type(&m) == MEM_TYPE_STATIC);
        TestMem(&m);
    }

    /* TestMem dynamic initializer expression */
    {
        mem_t m = MEM_DYNAMIC_INIT;
        OE_TEST(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    TestSHA();
    TestRandom();

    printf("=== passed all tests (mem)\n");

    return 0;
}
