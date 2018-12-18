// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstring>
#include "hostcalls_u.h"

static void _test_host_malloc(oe_enclave_t* enclave)
{
    void_ptr out_ptr;

    /* Try 0 size malloc. The returned pointer is implementation defined
     * but we should be able to free it. */
    OE_TEST(test_host_malloc(enclave, 0, &out_ptr) == OE_OK);
    OE_TEST(test_host_free(enclave, out_ptr) == OE_OK);

    /* Try malloc and see if the host can access it. */
    OE_TEST(test_host_malloc(enclave, 16, &out_ptr) == OE_OK);
    OE_TEST(out_ptr != NULL);

    /* Shouldn't crash since it's host memory. */
    memset(out_ptr, 0, 16);
    OE_TEST(test_host_free(enclave, out_ptr) == OE_OK);

    /* Make malloc fail. */
    OE_TEST(out_ptr != NULL);
    OE_TEST(test_host_malloc(enclave, ~((size_t)0), &out_ptr) == OE_OK);
    OE_TEST(out_ptr == NULL);
}

static void _test_host_calloc(oe_enclave_t* enclave)
{
    void_ptr out_ptr;

    /* Try with 0 arguments. Only thing we can do is free after we calloc. */
    OE_TEST(test_host_calloc(enclave, 0, 0, &out_ptr) == OE_OK);
    OE_TEST(test_host_free(enclave, out_ptr) == OE_OK);

    /* Try calloc and see if the host can access it. */
    OE_TEST(test_host_calloc(enclave, 16, 1, &out_ptr) == OE_OK);
    OE_TEST(out_ptr != NULL);

    /* Should be all zeros since it's host memory. */
    unsigned char expected[16] = {0};
    OE_TEST(memcmp(out_ptr, expected, 16) == 0);
    OE_TEST(test_host_free(enclave, out_ptr) == OE_OK);

    /* Make calloc fail. */
    OE_TEST(out_ptr != NULL);
    OE_TEST(test_host_calloc(enclave, ~((size_t)0), 1, &out_ptr) == OE_OK);
    OE_TEST(out_ptr == NULL);
}

OE_INLINE bool IsReallocBufferTestInitialized(void* ptr, size_t size)
{
    uint8_t* out_bytes = (uint8_t*)ptr;
    for (uint32_t i = 0; i < size; i++)
    {
        if (out_bytes[i] != TEST_HOSTREALLOC_INIT_VALUE)
            return false;
    }
    return true;
}

static void _test_host_realloc(oe_enclave_t* enclave)
{
    void_ptr out_ptr;

    /* oe_host_realloc with null ptr should behave like malloc */
    {
        oe_result_t result =
            test_host_realloc(enclave, NULL, 0, 1023, &out_ptr);
        OE_TEST(result == OE_OK);
        OE_TEST(out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(out_ptr, 1023));
    }

    /* oe_host_realloc to expand an existing pointer */
    {
        oe_result_t result =
            test_host_realloc(enclave, out_ptr, 1023, 65537, &out_ptr);
        OE_TEST(result == OE_OK);
        OE_TEST(out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(out_ptr, 65537));
    }

    /* oe_host_realloc no-op to same size buffer */
    {
        oe_result_t result =
            test_host_realloc(enclave, out_ptr, 65537, 65537, &out_ptr);
        OE_TEST(result == OE_OK);
        OE_TEST(out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(out_ptr, 65537));
    }

    /* oe_host_realloc to contract an existing pointer */
    {
        oe_result_t result =
            test_host_realloc(enclave, out_ptr, 65537, 1, &out_ptr);
        OE_TEST(result == OE_OK);
        OE_TEST(out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(out_ptr, 1));
    }

    /* oe_host_realloc to 0 size should free the pointer
     * This is not a behavior specified by C-standard, but we OE_TEST it for
     * consistency between compilers for enclave use.
     */
    {
        oe_result_t result =
            test_host_realloc(enclave, out_ptr, 1, 0, &out_ptr);
        OE_TEST(result == OE_OK);
        OE_TEST(!out_ptr);
    }

    /* oe_host_realloc of pointer from calloc.
     * Note that oe_host_realloc of host allocated buffers is not generally
     * supported, but in this case oe_host_malloc uses the same static-linked
     * libc in host anyway.
     */
    {
        size_t nmem = 8;
        size_t size = 512;
        void_ptr p = calloc(nmem, size);
        size_t old_size = nmem * size;
        size_t new_size = old_size + 1;
        oe_result_t result =
            test_host_realloc(enclave, p, old_size, new_size, &out_ptr);
        OE_TEST(result == OE_OK);

        // Resulting buffer should retain its original zero contents from calloc
        OE_TEST(out_ptr);
        uint8_t* out_bytes = (uint8_t*)out_ptr;
        for (uint32_t i = 0; i < old_size; i++)
        {
            OE_TEST(out_bytes[i] == 0);
        }

        /* TestHostRealloc only writes init value into expanded area for this
         * check */
        OE_TEST(out_bytes[old_size] == TEST_HOSTREALLOC_INIT_VALUE);

        free(out_ptr);
    }
}

static void _test_host_strndup(oe_enclave_t* enclave)
{
    char* out_str;

    /* NULL check. */
    out_str = (char*)0x1;
    OE_TEST(test_host_strndup(enclave, NULL, 0, &out_str) == OE_OK);
    OE_TEST(out_str == NULL);

    /* Empty string check. */
    OE_TEST(test_host_strndup(enclave, "", 0, &out_str) == OE_OK);
    OE_TEST(out_str != NULL);
    OE_TEST(out_str[0] == '\0');
    OE_TEST(test_host_free(enclave, out_str) == OE_OK);

    /* 0 size check. */
    OE_TEST(test_host_strndup(enclave, "hello", 0, &out_str) == OE_OK);
    OE_TEST(out_str != NULL);
    OE_TEST(out_str[0] == '\0');
    OE_TEST(test_host_free(enclave, out_str) == OE_OK);

    /* String length is greater than size. */
    OE_TEST(test_host_strndup(enclave, "hello", 2, &out_str) == OE_OK);
    OE_TEST(out_str != NULL);
    OE_TEST(memcmp(out_str, "he", 3) == 0);
    OE_TEST(test_host_free(enclave, out_str) == OE_OK);

    /* String length is less than size. */
    out_str = NULL;
    OE_TEST(test_host_strndup(enclave, "hello", 10, &out_str) == OE_OK);
    OE_TEST(out_str != NULL);
    OE_TEST(memcmp(out_str, "hello", 6) == 0);
    OE_TEST(test_host_free(enclave, out_str) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_hostcalls_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    _test_host_malloc(enclave);
    _test_host_calloc(enclave);
    _test_host_realloc(enclave);
    _test_host_strndup(enclave);

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
