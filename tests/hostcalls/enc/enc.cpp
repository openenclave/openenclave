// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_ECALL void TestHostMalloc(void* _args)
{
    /* Check arguments are outside the enclave. */
    TestHostMallocArgs* args = (TestHostMallocArgs*)_args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    args->outPtr = oe_host_malloc(args->inSize);
}

OE_ECALL void TestHostCalloc(void* _args)
{
    /* Check arguments are outside the enclave. */
    TestHostCallocArgs* args = (TestHostCallocArgs*)_args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    args->outPtr = oe_host_calloc(args->inNum, args->inSize);
}

OE_ECALL void TestHostRealloc(void* _args)
{
    TestHostReallocArgs args = *(TestHostReallocArgs*)_args;

    /* Check that pointers passed in are not enclave pointers */
    if (args.inPtr && args.oldSize > 0)
    {
        if (!oe_is_outside_enclave(args.inPtr, args.oldSize))
        {
            oe_abort();
            return;
        }
    }

    args.outPtr = oe_host_realloc(args.inPtr, args.newSize);

    /* Initialize only newly allocated bytes for verification by host */
    if (args.outPtr)
    {
        if (!args.inPtr)
        {
            oe_memset(args.outPtr, TEST_HOSTREALLOC_INIT_VALUE, args.newSize);
        }
        else if (args.oldSize < args.newSize)
        {
            void* extPtr = (void*)((uint64_t)args.outPtr + args.oldSize);
            oe_memset(
                extPtr,
                TEST_HOSTREALLOC_INIT_VALUE,
                args.newSize - args.oldSize);
        }
    }

    ((TestHostReallocArgs*)_args)->outPtr = args.outPtr;
}

OE_ECALL void TestHostStrndup(void* _args)
{
    /* Check arguments are outsid the enclave. */
    TestHostStrndupArgs* args = (TestHostStrndupArgs*)_args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    /* Check if string is outside the enclave. */
    TestHostStrndupArgs strndupArgs = *args;
    if (strndupArgs.inStr != NULL)
        OE_TEST(oe_is_outside_enclave(strndupArgs.inStr, strndupArgs.inSize));

    args->outStr = oe_host_strndup(strndupArgs.inStr, strndupArgs.inSize);
}

OE_ECALL void HostFree(void* args)
{
    oe_host_free(args);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
