// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include "switchless_nestedcalls_t.h"

void enc_ecall1_switchless(void)
{
    host_ocall1_switchless();
}

void enc_ecall2_switchless(void)
{
    host_ocall2_switchless();
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* AllowDebug */
    64,       /* HeapPageCount */
    64,       /* StackPageCount */
    NUM_TCS); /* TCSCount */
