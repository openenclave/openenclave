// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstring>
#include "../args.h"

static void _test_host_malloc(oe_enclave_t* enclave)
{
    TestHostMallocArgs args;

    /* Try 0 size malloc. The returned pointer is implementation defined
     * but we should be able to free it. */
    args.in_size = 0;
    args.out_ptr = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostMalloc", &args) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_ptr) == OE_OK);

    /* Try malloc and see if the host can access it. */
    args.in_size = 16;
    args.out_ptr = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostMalloc", &args) == OE_OK);
    OE_TEST(args.out_ptr != NULL);

    /* Shouldn't crash since it's host memory. */
    memset(args.out_ptr, 0, args.in_size);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_ptr) == OE_OK);

    /* Make malloc fail. */
    args.in_size = ~((size_t)0);
    OE_TEST(args.out_ptr != NULL);
    OE_TEST(oe_call_enclave(enclave, "TestHostMalloc", &args) == OE_OK);
    OE_TEST(args.out_ptr == NULL);
}

static void _test_host_calloc(oe_enclave_t* enclave)
{
    TestHostCallocArgs args;

    /* Try with 0 arguments. Only thing we can do is free after we calloc. */
    args.in_num = 0;
    args.in_size = 0;
    args.out_ptr = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostCalloc", &args) == OE_OK);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_ptr) == OE_OK);

    /* Try calloc and see if the host can access it. */
    args.in_num = 16;
    args.in_size = 1;
    args.out_ptr = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostCalloc", &args) == OE_OK);
    OE_TEST(args.out_ptr != NULL);

    /* Should be all zeros since it's host memory. */
    unsigned char expected[16] = {0};
    OE_TEST(memcmp(args.out_ptr, expected, args.in_size) == 0);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_ptr) == OE_OK);

    /* Make calloc fail. */
    args.in_num = ~((size_t)0);
    args.in_size = 1;
    OE_TEST(args.out_ptr != NULL);
    OE_TEST(oe_call_enclave(enclave, "TestHostCalloc", &args) == OE_OK);
    OE_TEST(args.out_ptr == NULL);
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
    TestHostReallocArgs args;

    /* oe_host_realloc with null ptr should behave like malloc */
    {
        args.in_ptr = NULL;
        args.old_size = 0;
        args.new_size = 1023;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(args.out_ptr, args.new_size));
    }

    /* oe_host_realloc to expand an existing pointer */
    {
        args.in_ptr = args.out_ptr;
        args.old_size = args.new_size;
        args.new_size = 65537;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(args.out_ptr, args.new_size));
    }

    /* oe_host_realloc no-op to same size buffer */
    {
        args.in_ptr = args.out_ptr;
        args.old_size = args.new_size;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(args.out_ptr, args.new_size));
    }

    /* oe_host_realloc to contract an existing pointer */
    {
        args.in_ptr = args.out_ptr;
        args.old_size = args.new_size;
        args.new_size = 1;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out_ptr);
        OE_TEST(IsReallocBufferTestInitialized(args.out_ptr, args.new_size));
    }

    /* oe_host_realloc to 0 size should free the pointer
     * This is not a behavior specified by C-standard, but we OE_TEST it for
     * consistency between compilers for enclave use.
     */
    {
        args.in_ptr = args.out_ptr;
        args.old_size = args.new_size;
        args.new_size = 0;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(!args.out_ptr);
    }

    /* oe_host_realloc of pointer from calloc.
     * Note that oe_host_realloc of host allocated buffers is not generally
     * supported, but in this case oe_host_malloc uses the same static-linked
     * libc in host anyway.
     */
    {
        size_t nmem = 8;
        size_t size = 512;
        args.in_ptr = calloc(nmem, size);
        args.old_size = nmem * size;
        args.new_size = args.old_size + 1;
        args.out_ptr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);

        // Resulting buffer should retain its original zero contents from calloc
        OE_TEST(args.out_ptr);
        uint8_t* out_bytes = (uint8_t*)args.out_ptr;
        for (uint32_t i = 0; i < args.old_size; i++)
        {
            OE_TEST(out_bytes[i] == 0);
        }

        /* TestHostRealloc only writes init value into expanded area for this
         * check */
        OE_TEST(out_bytes[args.old_size] == TEST_HOSTREALLOC_INIT_VALUE);

        free(args.out_ptr);
    }
}

static void _test_host_strndup(oe_enclave_t* enclave)
{
    TestHostStrndupArgs args;

    /* NULL check. */
    args.in_str = NULL;
    args.in_size = 0;
    args.out_str = (char*)0x1;
    OE_TEST(oe_call_enclave(enclave, "TestHostStrndup", &args) == OE_OK);
    OE_TEST(args.out_str == NULL);

    /* Empty string check. */
    args.in_str = "";
    args.in_size = 0;
    args.out_str = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostStrndup", &args) == OE_OK);
    OE_TEST(args.out_str != NULL);
    OE_TEST(args.out_str[0] == '\0');
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_str) == OE_OK);

    /* 0 size check. */
    args.in_str = "hello";
    args.in_size = 0;
    args.out_str = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostStrndup", &args) == OE_OK);
    OE_TEST(args.out_str != NULL);
    OE_TEST(args.out_str[0] == '\0');
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_str) == OE_OK);

    /* String length is greater than size. */
    args.in_str = "hello";
    args.in_size = 2;
    args.out_str = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostStrndup", &args) == OE_OK);
    OE_TEST(args.out_str != NULL);
    OE_TEST(memcmp(args.out_str, "he", 3) == 0);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_str) == OE_OK);

    /* String length is less than size. */
    args.in_str = "hello";
    args.in_size = 10;
    args.out_str = NULL;
    OE_TEST(oe_call_enclave(enclave, "TestHostStrndup", &args) == OE_OK);
    OE_TEST(args.out_str != NULL);
    OE_TEST(memcmp(args.out_str, "hello", 6) == 0);
    OE_TEST(oe_call_enclave(enclave, "HostFree", args.out_str) == OE_OK);
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

    if ((result = oe_create_enclave(
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
