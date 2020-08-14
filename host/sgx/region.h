// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _REGION_H
#define _REGION_H

#include <openenclave/bits/sgx/region.h>

typedef struct _oe_sgx_load_context oe_sgx_load_context_t;

struct oe_region_context
{
    /* The current virtual address */
    uint64_t vaddr;

    /* Region table */
    oe_region_t regions[OE_MAX_REGIONS];
    size_t num_regions;

    /* The encclave base address */
    uint64_t enclave_addr;

    /* The context needed to load SGX pages */
    oe_sgx_load_context_t* sgx_load_context;
};

#endif /* _REGION_H */
