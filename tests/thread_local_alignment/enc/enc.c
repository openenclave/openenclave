// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include "thread_local_alignment_t.h"

__attribute__((aligned(16))) __thread uint16_t data[1];

int enc_thread_local_alignment()
{
    /* test the access to the locale member in the pthread_self
     * specifically when using lld (currently only on Windows) */
    __ctype_get_mb_cur_max();

    /* avoid optimized out by the compiler */
    memset(data, 0, sizeof(data));

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
