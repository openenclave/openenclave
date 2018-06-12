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
        if (!OE_IsOutsideEnclave(args.inPtr, args.oldSize))
        {
            OE_Abort();
            return;
        }
    }

    args.outPtr = OE_HostRealloc(args.inPtr, args.newSize);

    /* Initialize only newly allocated bytes for verification by host */
    if (args.outPtr)
    {
        if (!args.inPtr)
        {
            OE_Memset(args.outPtr, TEST_HOSTREALLOC_INIT_VALUE, args.newSize);
        }
        else if (args.oldSize < args.newSize)
        {
            void* extPtr = (void*)((uint64_t)args.outPtr + args.oldSize);
            OE_Memset(
                extPtr,
                TEST_HOSTREALLOC_INIT_VALUE,
                args.newSize - args.oldSize);
        }
    }

    ((TestHostReallocArgs*)_args)->outPtr = args.outPtr;
}
