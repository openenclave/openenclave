// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_INLINE bool IsReallocBufferTestInitialized(void* ptr, size_t size)
{
    uint8_t* outBytes = (uint8_t*)ptr;
    for (uint32_t i = 0; i < size; i++)
    {
        if (outBytes[i] != TEST_HOSTREALLOC_INIT_VALUE)
            return false;
    }
    return true;
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

    TestHostReallocArgs args;

    /* oe_host_realloc with null ptr should behave like malloc */
    {
        args.inPtr = NULL;
        args.oldSize = 0;
        args.newSize = 1023;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.outPtr);
        OE_TEST(IsReallocBufferTestInitialized(args.outPtr, args.newSize));
    }

    /* oe_host_realloc to expand an existing pointer */
    {
        args.inPtr = args.outPtr;
        args.oldSize = args.newSize;
        args.newSize = 65537;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.outPtr);
        OE_TEST(IsReallocBufferTestInitialized(args.outPtr, args.newSize));
    }

    /* oe_host_realloc no-op to same size buffer */
    {
        args.inPtr = args.outPtr;
        args.oldSize = args.newSize;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.outPtr);
        OE_TEST(IsReallocBufferTestInitialized(args.outPtr, args.newSize));
    }

    /* oe_host_realloc to contract an existing pointer */
    {
        args.inPtr = args.outPtr;
        args.oldSize = args.newSize;
        args.newSize = 1;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.outPtr);
        OE_TEST(IsReallocBufferTestInitialized(args.outPtr, args.newSize));
    }

    /* oe_host_realloc to 0 size should free the pointer
     * This is not a behavior specified by C-standard, but we OE_TEST it for
     * consistency between compilers for enclave use.
     */
    {
        args.inPtr = args.outPtr;
        args.oldSize = args.newSize;
        args.newSize = 0;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(!args.outPtr);
    }

    /* oe_host_realloc of pointer from calloc.
     * Note that oe_host_realloc of host allocated buffers is not generally
     * supported, but in this case oe_host_malloc uses the same static-linked
     * libc in host anyway.
     */
    {
        size_t nmem = 8;
        size_t size = 512;
        args.inPtr = calloc(nmem, size);
        args.oldSize = nmem * size;
        args.newSize = args.oldSize + 1;
        args.outPtr = NULL;
        oe_result_t result = oe_call_enclave(enclave, "TestHostRealloc", &args);
        OE_TEST(result == OE_OK);

        // Resulting buffer should retain its original zero contents from calloc
        OE_TEST(args.outPtr);
        uint8_t* outBytes = (uint8_t*)args.outPtr;
        for (uint32_t i = 0; i < args.oldSize; i++)
        {
            OE_TEST(outBytes[i] == 0);
        }

        /* TestHostRealloc only writes init value into expanded area for this
         * check */
        OE_TEST(outBytes[args.oldSize] == TEST_HOSTREALLOC_INIT_VALUE);

        free(args.outPtr);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
