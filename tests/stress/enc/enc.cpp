// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include "stress_t.h"

static int rcv = 0;

void do_ecall(int arg)
{
    // almost do nothing
    rcv = arg + 1;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8,    /* HeapPageCount */
    8,    /* StackPageCount */
    1);   /* TCSCount */