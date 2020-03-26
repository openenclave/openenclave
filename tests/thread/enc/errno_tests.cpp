// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _PTHREAD_ENC_
#include "thread.h"
#endif

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include "errno.h"
#include "thread_t.h"

void* enc_malloc(size_t size, int* err)
{
    void* ret = malloc(size);
    *err = errno;
    return ret;
}

int64_t enc_strtol(const char* nptr, int base, int* err)
{
    long ret = strtol(nptr, NULL, base);
    *err = errno;
    return ret;
}
