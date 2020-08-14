// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>
#include "region_t.h"

#define printf oe_host_printf

#define REGION_ID 1001

int region_ecall(void)
{
    oe_region_t region;
    const uint8_t* base;
    const uint8_t* ptr;

    assert((base = __oe_get_enclave_base()));
    assert(oe_region_get(REGION_ID, &region) == OE_OK);
    ptr = base + region.vaddr;

    /* The region should occur right after the relocation section */
    assert(region.id == REGION_ID);
    assert(region.vaddr == (uint64_t)((uint8_t*)__oe_get_reloc_end() - base));
    assert(region.size == 4096);
    assert(!region.is_elf);

    for (size_t i = 0; i < OE_PAGE_SIZE; i++)
        assert(ptr[i] == 0xAB);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
