// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>

#include "core_u.h"

void oe_write_ocall(int device, const char* str, size_t maxlen)
{
    if (str && (device == 0 || device == 1))
    {
        FILE* stream = (device == 0) ? stdout : stderr;
        size_t len = strnlen(str, maxlen);
        fprintf(stream, "%.*s", (int)len, str);
        fflush(stream);
    }
}
