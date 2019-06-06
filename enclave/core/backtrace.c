// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    char** ret = NULL;
    oe_backtrace_symbols_args_t* args = NULL;

    if (!buffer || size > OE_BACKTRACE_MAX)
        goto done;

    if (!(args = oe_host_malloc(sizeof(oe_backtrace_symbols_args_t))))
        goto done;

    if (oe_memcpy_s(
            args->buffer,
            sizeof(void*) * OE_BACKTRACE_MAX,
            buffer,
            sizeof(void*) * (size_t)size) != OE_OK)
        goto done;
    args->size = size;
    args->ret = NULL;

    if (oe_ocall(
            OE_OCALL_BACKTRACE_SYMBOLS,
            (uint64_t)args,
            sizeof(*args),
            true,
            NULL,
            0) != OE_OK)
        goto done;

    ret = args->ret;

done:

    if (args)
        oe_host_free(args);

    return ret;
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
    oe_host_free(syms);

    result = OE_OK;

done:
    return result;
}
