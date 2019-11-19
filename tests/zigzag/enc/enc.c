// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include "zigzag_t.h"

void enc_zig(int enc_num)
{
    printf("enclave %d zig!\n", enc_num);
    host_zag();
}

void enc_zag(int enc_num)
{
    printf("enclave %d zag!\n", enc_num);
    host_bye();
}


OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    64, /* HeapPageCount */
    64, /* StackPageCount */
    1);   /* TCSCount */
