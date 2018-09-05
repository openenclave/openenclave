// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include "../args.h"

char* oe_host_stack_strdup(const char* str)
{
    size_t n = oe_strlen(str);

    char* dup = (char*)oe_host_alloc_for_call_host(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}

OE_ECALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    if (!oe_is_outside_enclave(args, sizeof(EchoArgs)))
    {
        args->ret = -1;
        return;
    }

    if (oe_strcmp(args->in, "Hello World") != 0)
    {
        args->ret = -1;
        return;
    }

    args->str1 = oe_host_stack_strdup("oe_host_stack_strdup1");
    args->str2 = oe_host_stack_strdup("oe_host_stack_strdup2");
    args->str3 = oe_host_stack_strdup("oe_host_stack_strdup3");

    if (oe_call_host("Echo", args) != OE_OK)
    {
        args->ret = -1;
        return;
    }

    oe_host_printf("Hello from Echo function!\n");

    oe_host_free_for_call_host(args->str3);
    oe_host_free_for_call_host(args->str2);
    oe_host_free_for_call_host(args->str1);

    args->ret = 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
