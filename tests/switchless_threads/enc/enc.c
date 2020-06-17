// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "switchless_threads_t.h"

#define STRING_LEN 100
#define STRING_HELLO "Hello World"
#define HOST_PARAM_STRING "host string parameter"
#define HOST_STACK_STRING "host string on stack"

int enc_echo_single(char* in, char out[100])
{
    oe_result_t result;

    if (oe_strcmp(in, STRING_HELLO) != 0)
    {
        return -1;
    }

    char stack_allocated_str[STRING_LEN] = HOST_STACK_STRING;
    int return_val;

    result = host_echo_regular(
        &return_val, in, out, HOST_PARAM_STRING, stack_allocated_str);

    if (result != OE_OK || return_val != 0)
        return -1;

    result = host_echo_switchless(
        &return_val, in, out, HOST_PARAM_STRING, stack_allocated_str);

    if (result != OE_OK || return_val != 0)
        return -1;

    return 0;
}

int enc_echo_multiple(char* in, char out[STRING_LEN], int repeats)
{
    oe_result_t result;

    if (oe_strcmp(in, STRING_HELLO) != 0)
    {
        return -1;
    }

    char stack_allocated_str[STRING_LEN] = HOST_STACK_STRING;
    int return_val;

    for (int i = 0; i < repeats; i++)
    {
        result = host_echo_regular(
            &return_val, in, out, HOST_PARAM_STRING, stack_allocated_str);
        if (result != OE_OK || return_val != 0)
            return -1;

        result = host_echo_switchless(
            &return_val, in, out, HOST_PARAM_STRING, stack_allocated_str);
        if (result != OE_OK || return_val != 0)
            return -1;
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    128,  /* NumStackPages */
    8);   /* NumTCS */
