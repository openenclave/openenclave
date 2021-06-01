// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>
#include "sgxextra_t.h"

#define printf oe_host_printf

int sgxextra_ecall(void)
{
    const uint8_t* heap = __oe_get_heap_base();
    assert(heap != NULL);

    const uint8_t* page = heap - OE_PAGE_SIZE;

    /* check contents of extra page */
    for (size_t i = 0; i < OE_PAGE_SIZE; i++)
    {
        assert(page[i] == 0xab);
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
