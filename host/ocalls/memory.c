// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "core_u.h"

void* oe_realloc_ocall(void* ptr, size_t size)
{
    return realloc(ptr, size);
}
