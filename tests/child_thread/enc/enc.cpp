// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "child_thread_t.h"

void get_magic_ecall(void* pdata)
{
    if (pdata != 0)
    {
        *((uint32_t*)pdata) = 0x1234;
    }
}

int stay_in_ecall()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    return 0;
}

int stay_in_ocall_ecall()
{
    stay_ocall();
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8,    /* HeapPageCount */
    8,    /* StackPageCount */
    4);   /* TCSCount */
