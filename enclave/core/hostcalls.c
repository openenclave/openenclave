// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include "td.h"

void* oe_host_malloc(size_t size)
{
    uint64_t argIn = size;
    uint64_t argOut = 0;

    if (oe_ocall(OE_OCALL_MALLOC, argIn, &argOut) != OE_OK)
    {
        return NULL;
    }

    if (!oe_is_outside_enclave((void*)argOut, size))
        oe_abort();

    return (void*)argOut;
}

void* oe_host_calloc(size_t nmemb, size_t size)
{
    void* ptr = oe_host_malloc(nmemb * size);

    if (ptr)
        oe_memset(ptr, 0, nmemb * size);

    return ptr;
}

void* oe_host_realloc(void* ptr, size_t size)
{
    oe_realloc_args_t* argIn = NULL;
    uint64_t argOut = 0;

    if (!(argIn = (oe_realloc_args_t*)oe_host_alloc_for_call_host(
              sizeof(oe_realloc_args_t))))
        goto done;

    argIn->ptr = ptr;
    argIn->size = size;

    if (oe_ocall(OE_OCALL_REALLOC, (uint64_t)argIn, &argOut) != OE_OK)
    {
        argOut = 0;
        goto done;
    }

    if (argOut && !oe_is_outside_enclave((void*)argOut, size))
        oe_abort();

done:
    oe_host_free_for_call_host(argIn);
    return (void*)argOut;
}

void oe_host_free(void* ptr)
{
    oe_ocall(OE_OCALL_FREE, (uint64_t)ptr, NULL);
}

char* oe_host_strndup(const char* str, size_t n)
{
    char* p;
    size_t len;

    if (!str)
        return NULL;

    len = oe_strlen(str);

    if (n < len)
        len = n;

    if (!(p = oe_host_malloc(len + 1)))
        return NULL;

    oe_memcpy(p, str, len);
    p[len] = '\0';

    return p;
}

int oe_host_write(int device, const char* str, size_t len)
{
    int ret = -1;
    oe_print_args_t* args = NULL;

    /* Reject invalid arguments */
    if ((device != 0 && device != 1) || !str)
        goto done;

    /* Determine the length of the string */
    if (len == (size_t)-1)
        len = oe_strlen(str);

    /* Allocate space for the arguments followed by null-terminated string */
    if (!(args = (oe_print_args_t*)oe_host_alloc_for_call_host(
              sizeof(oe_print_args_t) + len + 1)))
    {
        goto done;
    }

    /* Initialize the arguments */
    args->device = device;
    args->str = (char*)(args + 1);
    oe_memcpy(args->str, str, len);
    args->str[len] = '\0';

    /* Perform OCALL */
    if (oe_ocall(OE_OCALL_WRITE, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = 0;

done:
    oe_host_free_for_call_host(args);
    return ret;
}

int oe_host_vfprintf(int device, const char* fmt, oe_va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;

    /* Try first with a fixed-length scratch buffer */
    {
        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(buf, sizeof(buf), fmt, ap);
        oe_va_end(ap);
    }

    /* If string was truncated, retry with correctly sized buffer */
    if (n >= sizeof(buf))
    {
        if (!(p = oe_stack_alloc(n + 1)))
            return -1;

        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(p, n + 1, fmt, ap);
        oe_va_end(ap);
    }

    oe_host_write(device, p, (size_t)-1);

    return n;
}

int oe_host_printf(const char* fmt, ...)
{
    int n;

    oe_va_list ap;
    oe_va_start(ap, fmt);
    n = oe_host_vfprintf(0, fmt, ap);
    oe_va_end(ap);

    return n;
}

int oe_host_fprintf(int device, const char* fmt, ...)
{
    int n;

    oe_va_list ap;
    oe_va_start(ap, fmt);
    n = oe_host_vfprintf(device, fmt, ap);
    oe_va_end(ap);

    return n;
}
