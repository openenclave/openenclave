// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/vector.h>
#include "internal_t.h"

/* Backtrace must use the internal allocator to bypass debug-malloc. */
void* dlmalloc(size_t size);
void dlfree(void* ptr);
void* dlrealloc(void* ptr, size_t size);

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    char** ret = NULL;
    void* buf = NULL;
    const size_t BUF_SIZE = 4096;
    size_t buf_size = BUF_SIZE;
    size_t buf_size_out;
    uint32_t retval;
    char** argv = NULL;

    if (!buffer || size < 0)
        goto done;

    if (!(buf = dlmalloc(buf_size)))
        goto done;

    /* First call might return OE_BUFFER_TOO_SMALL. */
    if (oe_backtrace_symbols_ocall(
            &retval,
            oe_get_enclave(),
            (const uint64_t*)buffer,
            (size_t)size,
            buf,
            buf_size,
            &buf_size_out) != OE_OK)
    {
        goto done;
    }

    /* Second call uses buffer size returned by first call. */
    if ((oe_result_t)retval == OE_BUFFER_TOO_SMALL)
    {
        buf_size = buf_size_out;

        if (!(buf = dlrealloc(buf, buf_size)))
            goto done;

        if (oe_backtrace_symbols_ocall(
                &retval,
                oe_get_enclave(),
                (const uint64_t*)buffer,
                (size_t)size,
                buf,
                buf_size,
                &buf_size_out) != OE_OK)
        {
            goto done;
        }

        if ((oe_result_t)retval != OE_OK)
            goto done;
    }
    else if ((oe_result_t)retval != OE_OK)
    {
        goto done;
    }

    /* Convert vector to array of strings. */
    {
        oe_vector_t* vec;

        if (!(vec = oe_vector_relocate(buf, (size_t)size)))
            goto done;

        if (!(argv = oe_vector_to_argv(vec, (size_t)size, dlmalloc, dlfree)))
        {
            goto done;
        }
    }

    ret = argv;
    argv = NULL;

done:

    if (buf)
        dlfree(buf);

    if (argv)
        dlfree(argv);

    return ret;
}

void oe_backtrace_symbols_free(char** ptr)
{
    dlfree(ptr);
}

oe_result_t oe_print_backtrace(void)
{
    oe_result_t result = OE_UNEXPECTED;
    void* buffer[OE_BACKTRACE_MAX];
    int size;
    char** syms = NULL;

    if ((size = oe_backtrace(buffer, OE_BACKTRACE_MAX)) <= 0)
        OE_RAISE(OE_FAILURE);

    if (!(syms = oe_backtrace_symbols(buffer, size)))
        OE_RAISE(OE_FAILURE);

    oe_host_printf("=== backtrace:\n");

    for (int i = 0; i < size; i++)
        oe_host_printf("%s(): %p\n", syms[i], buffer[i]);

    oe_host_printf("\n");
    oe_backtrace_symbols_free(syms);

    result = OE_OK;

done:
    return result;
}
