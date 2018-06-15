// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include "../args.h"

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
