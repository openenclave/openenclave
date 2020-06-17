// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>

#include "atexit_t.h"

void get_magic_ecall(void* pdata)
{
    if (pdata != 0)
    {
        *((uint32_t*)pdata) = 0x1234;
    }
}

// this function would be called by atexit
void exit_function_call_increase(void)
{
    //++global_var1;
    global_variable_increase_ocall();
}

void atexit_1_call_ecall(void)
{
    atexit(exit_function_call_increase);
}

// atexit should at least support 32 call back functions
void atexit_32_call_ecall(void)
{
    for (int i = 0; i < 32; i++)
    {
        atexit(exit_function_call_increase);
    }
}

// ocall->ecall
void exit_function_call_an_ecall(void)
{
    with_an_ecall_ocall();
}

void atexit_with_ecall_ecall(void)
{
    atexit(exit_function_call_an_ecall);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
