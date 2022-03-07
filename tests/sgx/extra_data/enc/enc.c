// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>
#include "extra_data_t.h"

int extra_data_ecall(void)
{
    const uint8_t* heap = __oe_get_heap_base();
    OE_TEST(heap != NULL);

    const uint8_t* page = heap - OE_PAGE_SIZE;

    /* check contents of extra page */
    for (size_t i = 0; i < OE_PAGE_SIZE; i++)
    {
        OE_TEST(page[i] == 0xab);
    }

    return 0;
}
