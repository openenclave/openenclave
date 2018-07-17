// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/backtrace_symbols.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

const char* arg0;

static const char* _symbols[] = {
    "GetBacktrace",
    "Test",
    "_HandleCallEnclave",
    "_HandleECall",
    "__oe_handle_main",
    "oe_enter",
};

int _num_symbols = OE_COUNTOF(_symbols);

static void _print_backtrace(
    oe_enclave_t* enclave,
    void* const* buffer,
    int size)
{
    char** symbols = oe_backtrace_symbols(enclave, buffer, size);
    OE_TEST(symbols != NULL);

    printf("=== backtrace:\n");

    for (int i = 0; i < size; i++)
        printf("%s(): (%p)\n", symbols[i], buffer[i]);

    OE_TEST(size == _num_symbols);

    for (int i = 0; i < size; i++)
        OE_TEST(strcmp(_symbols[i], symbols[i]) == 0);

    free(symbols);
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    r = oe_create_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    Args args;
    args.size = 0;
    r = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(r == OE_OK);

    _print_backtrace(enclave, args.buffer, args.size);

    if (args.size <= 0)
    {
        fprintf(stderr, "%s: backtrace failed\n", argv[0]);
        exit(1);
    }

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
