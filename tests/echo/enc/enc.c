// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include "../args.h"

char* OE_HostStackStrdup(const char* str)
{
    size_t n = OE_Strlen(str);

    char* dup = (char*)OE_HostAllocForCallHost(n + 1);

    if (dup)
        OE_Memcpy(dup, str, n + 1);

    return dup;
}

OE_ECALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    if (!OE_IsOutsideEnclave(args, sizeof(EchoArgs)))
    {
        args->ret = -1;
        return;
    }

    if (OE_Strcmp(args->in, "Hello World") != 0)
    {
        args->ret = -1;
        return;
    }

    args->str1 = OE_HostStackStrdup("OE_HostStackStrdup1");
    args->str2 = OE_HostStackStrdup("OE_HostStackStrdup2");
    args->str3 = OE_HostStackStrdup("OE_HostStackStrdup3");

    if (OE_CallHost("Echo", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    OE_HostPrintf("Hello from Echo function!\n");

    OE_HostFreeForCallHost(args->str3);
    OE_HostFreeForCallHost(args->str2);
    OE_HostFreeForCallHost(args->str1);

    args->ret = 0;
}
