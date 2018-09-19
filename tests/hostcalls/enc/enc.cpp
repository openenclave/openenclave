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

    args->out_ptr = oe_host_malloc(args->in_size);
}

OE_ECALL void TestHostCalloc(void* _args)
{
    /* Check arguments are outside the enclave. */
    TestHostCallocArgs* args = (TestHostCallocArgs*)_args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    args->out_ptr = oe_host_calloc(args->in_num, args->in_size);
}

OE_ECALL void TestHostRealloc(void* _args)
{
    TestHostReallocArgs args = *(TestHostReallocArgs*)_args;

    /* Check that pointers passed in are not enclave pointers */
    if (args.in_ptr && args.old_size > 0)
    {
        if (!oe_is_outside_enclave(args.in_ptr, args.old_size))
        {
            oe_abort();
            return;
        }
    }

    args.out_ptr = oe_host_realloc(args.in_ptr, args.new_size);

    /* Initialize only newly allocated bytes for verification by host */
    if (args.out_ptr)
    {
        if (!args.in_ptr)
        {
            oe_memset(args.out_ptr, TEST_HOSTREALLOC_INIT_VALUE, args.new_size);
        }
        else if (args.old_size < args.new_size)
        {
            void* ext_ptr = (void*)((uint64_t)args.out_ptr + args.old_size);
            oe_memset(
                ext_ptr,
                TEST_HOSTREALLOC_INIT_VALUE,
                args.new_size - args.old_size);
        }
    }

    ((TestHostReallocArgs*)_args)->out_ptr = args.out_ptr;
}

OE_ECALL void TestHostStrndup(void* _args)
{
    /* Check arguments are outsid the enclave. */
    TestHostStrndupArgs* args = (TestHostStrndupArgs*)_args;
    OE_TEST(args != NULL);
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    /* Check if string is outside the enclave. */
    TestHostStrndupArgs strndup_args = *args;
    if (strndup_args.in_str != NULL)
        OE_TEST(
            oe_is_outside_enclave(strndup_args.in_str, strndup_args.in_size));

    args->out_str = oe_host_strndup(strndup_args.in_str, strndup_args.in_size);
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
