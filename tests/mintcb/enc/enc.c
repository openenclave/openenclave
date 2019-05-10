// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include "mintcb_t.h"

int test_mintcb_ecall(int value)
{
    int retval = -1;

    oe_printf("enclave: test_mintcb_ecall()\n");

    if (test_mintcb_ocall(&retval, value) != OE_OK)
        return -1;

    return retval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
