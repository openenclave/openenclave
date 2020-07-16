// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include "split_t.h"

#define printf oe_host_printf

static void callback(const char* msg)
{
    oe_host_printf("callback(%s)\n", msg);
}

int split_ecall(void)
{
    typedef void (*start_t)(void (*callback)(const char* msg));
    start_t start = __oe_get_isolated_image_entry_point();

    oe_assert(start);

    (*start)(callback);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
