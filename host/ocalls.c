// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

#include "core_u.h"
#include "ocalls.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void* oe_realloc_ocall(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void oe_log_ocall(uint32_t log_level, const char* message)
{
    oe_log_message(true, (oe_log_level_t)log_level, message);
}

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
