// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "echo_t.h"

char* oe_host_strdup(const char* str)
{
    size_t n = oe_strlen(str);

    char* dup = (char*)oe_host_calloc(1, n + 1);

    if (dup)
        memcpy(dup, str, n + 1);

    return dup;
}

int enc_echo(char* in, char out[100])
{
    oe_result_t result;

    if (oe_strcmp(in, "Hello World") != 0)
    {
        return -1;
    }

    char* host_allocated_str = oe_host_strdup("oe_host_strdup2");
    if (host_allocated_str == NULL)
    {
        return -1;
    }

    char stack_allocated_str[100] = "oe_host_strdup3";
    int return_val;

    result = host_echo(
        &return_val,
        in,
        out,
        "oe_host_strdup1",
        host_allocated_str,
        stack_allocated_str,
        sizeof(stack_allocated_str));
    if (result != OE_OK)
    {
        return -1;
    }

    if (return_val != 0)
    {
        return -1;
    }

    oe_host_printf("Hello from Echo function!\n");

    oe_host_free(host_allocated_str);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
