// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <string.h>
#include "switchless_t.h"

#define STRING_LEN 100
#define STRING_HELLO "Hello World"
#define HOST_PARAM_STRING "host string parameter"
#define HOST_STACK_STRING "host string on stack"

int enc_test_echo_switchless(const char* in, char out[STRING_LEN], int repeats)
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
        result = host_echo_switchless(
            &return_val, in, out, HOST_PARAM_STRING, stack_allocated_str);
        if (result != OE_OK)
        {
            return -1;
        }

        if (return_val != 0)
        {
            return -1;
        }
    }

    oe_host_printf("Enclave: Hello from switchless Echo function!\n");

    return 0;
}

int enc_test_echo_regular(const char* in, char out[STRING_LEN], int repeats)
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
        if (result != OE_OK)
        {
            return -1;
        }

        if (return_val != 0)
        {
            return -1;
        }
    }

    oe_host_printf("Enclave: Hello from regular Echo function!\n");

    return 0;
}

int enc_echo_switchless(
    const char* in,
    char* out,
    const char* str1,
    char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "enclave string parameter") == 0);
    OE_TEST(strcmp(str2, "enclave string on stack") == 0);

    strcpy(out, in);

    return 0;
}

int enc_echo_regular(
    const char* in,
    char* out,
    const char* str1,
    char str2[STRING_LEN])
{
    OE_TEST(strcmp(str1, "enclave string parameter") == 0);
    OE_TEST(strcmp(str2, "enclave string on stack") == 0);

    strcpy(out, in);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    64,       /* NumHeapPages */
    64,       /* NumStackPages */
    NUM_TCS); /* NumTCS */
