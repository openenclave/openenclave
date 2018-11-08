// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include "td.h"

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
    oe_realloc_args_t* arg_in = NULL;
    uint64_t arg_out = 0;

    if (!(arg_in =
              (oe_realloc_args_t*)oe_host_calloc(1, sizeof(oe_realloc_args_t))))
        goto done;

    arg_in->ptr = ptr;
    arg_in->size = size;

    if (oe_ocall(OE_OCALL_REALLOC, (uint64_t)arg_in, &arg_out) != OE_OK)
    {
        arg_out = 0;
        goto done;
    }

    if (arg_out && !oe_is_outside_enclave((void*)arg_out, size))
        oe_abort();

done:
    oe_host_free(arg_in);
    return (void*)arg_out;
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

    /* Check for integer overflow and allocate space for the arguments followed
     * by null-terminated string */
    size_t total_size;
    if (oe_safe_add_sizet(len, 1 + sizeof(oe_print_args_t), &total_size) !=
        OE_OK)
        goto done;

    if (!(args = (oe_print_args_t*)oe_host_calloc(1, total_size)))
        goto done;

    /* Initialize the arguments */
    args->device = device;
    args->str = (char*)(args + 1);

    if (oe_memcpy_s(args->str, len, str, len) != OE_OK)
        goto done;

    args->str[len] = '\0';

    /* Perform OCALL */
    if (oe_ocall(OE_OCALL_WRITE, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = 0;

done:
    oe_host_free(args);
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
        if (!(p = oe_malloc(n + 1)))
            return -1;

        oe_va_list ap;
        oe_va_copy(ap, ap_);
        n = oe_vsnprintf(p, (size_t)n + 1, fmt, ap);
        oe_va_end(ap);
    }

    oe_host_write(device, p, (size_t)-1);
    if (buf != p)
    {
        oe_free(p);
    }
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

// Function used by oeedger8r for allocating ocall buffers.
void* oe_allocate_ocall_buffer(size_t size)
{
    return oe_host_malloc(size);
}

// Function used by oeedger8r for freeing ocall buffers.
void oe_free_ocall_buffer(void* buffer)
{
    oe_host_free(buffer);
}
