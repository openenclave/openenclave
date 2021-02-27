// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <string.h>

void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)
{
    if (len > destlen)
        oe_abort();
    return memcpy(dest, src, len);
}

void* __memset_chk(void* dest, int c, size_t len, size_t destlen)
{
    if (len > destlen)
        oe_abort();
    return memset(dest, c, len);
}
