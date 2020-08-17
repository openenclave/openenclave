// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _REGION_H
#define _REGION_H

#include <openenclave/internal/debugrt/host.h>
#include <openenclave/bits/sgx/region.h>
#include <limits.h>

typedef struct _oe_sgx_load_context oe_sgx_load_context_t;

struct oe_region_context
{
    /* The current virtual address */
    uint64_t vaddr;

    /* Region table */
    oe_region_t regions[OE_MAX_REGIONS];
    size_t num_regions;

    /* The enclave base address */
    uint64_t enclave_addr;

    /* The context needed to load SGX pages */
    oe_sgx_load_context_t* sgx_load_context;

    /* PATH of the current image */
    char* path;

    oe_debug_image_t debug_images[OE_MAX_REGIONS];
    size_t num_debug_images;
};

oe_result_t oe_region_debug_notify_loaded(oe_region_context_t* context);

oe_result_t oe_region_debug_notify_unloaded(oe_region_context_t* context);

#endif /* _REGION_H */
