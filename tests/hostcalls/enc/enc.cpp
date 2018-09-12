// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include "../args.h"

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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
