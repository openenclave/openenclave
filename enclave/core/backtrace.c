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
