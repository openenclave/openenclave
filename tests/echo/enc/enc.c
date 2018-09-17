// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include "echo_t.h"

char* oe_host_strdup(const char* str)
{
    size_t n = oe_strlen(str);

    char* dup = (char*)oe_host_alloc_for_call_host(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}

int enc_echo(char* in, char out[100])
{
    oe_result_t result;

    if (oe_strcmp(in, "Hello World") != 0)
    {
        return -1;
    }

    char* hostAllocatedStr = oe_host_strdup("oe_host_strdup2");
    if (hostAllocatedStr == NULL)
    {
        return -1;
    }

    char stackAllocatedStr[100] = "oe_host_strdup3";
    int returnVal;

    result = host_echo(
        &returnVal,
        in,
        out,
        "oe_host_strdup1",
        hostAllocatedStr,
        stackAllocatedStr);
    if (result != OE_OK)
    {
        return -1;
    }

    if (returnVal != 0)
    {
        return -1;
    }

    oe_host_printf("Hello from Echo function!\n");

    oe_host_free_for_call_host(hostAllocatedStr);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
