// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include "stress_t.h"

void do_ecall(int arg)
{
    oe_host_printf("Do ecall time: %d\n", arg);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    8,    /* HeapPageCount */
    8,    /* StackPageCount */
    1);   /* TCSCount */
