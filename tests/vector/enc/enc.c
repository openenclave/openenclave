// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/vector.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vector_t.h"

void test_vector_ecall(void)
{
    oe_vector_t vectors1[] = {
        {"red", 4},
        {"green", 6},
        {"blue", 5},
    };
    void* buf;
    size_t buf_size;
    size_t vector_count = sizeof(vectors1) / sizeof(vectors1[0]);
    oe_vector_t* vectors2;
    char** argv;

    OE_TEST(
        oe_vector_pack(vectors1, vector_count, &buf, &buf_size, malloc, free) ==
        OE_OK);

    vectors2 = oe_vector_relocate(buf, vector_count);

    for (size_t i = 0; i < vector_count; i++)
    {
        const char* s1 = (const char*)vectors1[i].data;
        const char* s2 = (const char*)vectors2[i].data;
        size_t len1 = strlen(s1);
        size_t len2 = strlen(s2);
        size_t size1 = vectors1[i].size;
        size_t size2 = vectors2[i].size;

        OE_TEST(size1 == size2);
        OE_TEST(strcmp(s1, s2) == 0);
        OE_TEST(len1 == len2);
    }

    OE_TEST(argv = oe_vector_to_argv(vectors1, vector_count, malloc, free));

    for (size_t i = 0; i < vector_count; i++)
    {
        printf("argv[i]=%s\n", argv[i]);
        OE_TEST(strcmp(argv[i], (const char*)vectors1[i].data) == 0);
    }

    OE_TEST(argv[vector_count] == NULL);

    free(buf);
    free(argv);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
