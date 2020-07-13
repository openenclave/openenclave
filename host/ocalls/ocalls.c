// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>

#include "core_u.h"
#include "ocalls.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}
