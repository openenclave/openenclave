// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "switchless_atexit_calls_t.h"

int enc_ecall_switchless()
{
    return 0x5678;
}

__attribute__((destructor)) void atexit_with_switchless_ocalls()
{
    host_ocall1_switchless(0x1234);
}

__attribute__((destructor)) void atexit_with_switchless_nested_calls()
{
    host_ocall2_switchless();
}

OE_SET_ENCLAVE_SGX(
    1,                             /* ProductID */
    1,                             /* SecurityVersion */
    true,                          /* Debug */
    OE_TEST_MT_HEAP_SIZE(NUM_TCS), /* NumHeapPages */
    64,                            /* NumStackPages */
    NUM_TCS);                      /* NumTCS */
