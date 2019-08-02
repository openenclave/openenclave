// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

#include "ocalls.h"
#include "tee_u.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void* oe_realloc_ocall(void* ptr, size_t size)
{
    return realloc(ptr, size);
}

void* oe_memset_ocall(void* ptr, int value, size_t size)
{
    return memset(ptr, value, size);
}

char* oe_strndup_ocall(const char* str, size_t n)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = strlen(str);

    if (n < len)
        len = n;

    /* Would be an integer overflow in the next statement. */
    if (len == OE_SIZE_MAX)
        return NULL;

    if (!(p = malloc(len + 1)))
        return NULL;

    memcpy(p, str, len);
    p[len] = '\0';

    return p;
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
