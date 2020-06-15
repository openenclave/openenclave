// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/stack_alloc.h>

#include "core_t.h"

void* oe_host_malloc(size_t size)
{
    uint64_t arg_in = size;
    uint64_t arg_out = 0;

    if (oe_ocall(OE_OCALL_MALLOC, arg_in, &arg_out) != OE_OK)
    {
        return NULL;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, size))
        oe_abort();

    return (void*)arg_out;
}

void* oe_host_calloc(size_t nmemb, size_t size)
{
    size_t total_size;
    if (oe_safe_mul_sizet(nmemb, size, &total_size) != OE_OK)
        return NULL;

    void* ptr = oe_host_malloc(total_size);

    if (ptr)
        oe_memset_s(ptr, nmemb * size, 0, nmemb * size);

    return ptr;
}

void* oe_host_realloc(void* ptr, size_t size)
{
    void* retval = NULL;

    if (!ptr)
        return oe_host_malloc(size);

    if (oe_realloc_ocall(&retval, ptr, size) != OE_OK)
        return NULL;

    if (retval && !oe_is_outside_enclave(retval, size))
    {
        oe_assert("oe_host_realloc_ocall() returned non-host memory" == NULL);
        oe_abort();
    }

    return retval;
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

    /* Would be an integer overflow in the next statement. */
    if (len == OE_SIZE_MAX)
        return NULL;

    if (!(p = oe_host_malloc(len + 1)))
        return NULL;

    if (oe_memcpy_s(p, len + 1, str, len) != OE_OK)
        return NULL;
    p[len] = '\0';

    return p;
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
    if (n >= (int)sizeof(buf))
    {
        if (!(p = oe_stack_alloc((uint32_t)n + 1)))
            return -1;

        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(p, (size_t)n + 1, fmt, ap);
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

int oe_host_write(int device, const char* str, size_t len)
{
    if (oe_write_ocall(device, str, len) != OE_OK)
        return -1;

    return 0;
}
