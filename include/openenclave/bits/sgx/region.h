// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_REGION_H
#define _OE_INTERNAL_REGION_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_MAX_REGIONS 16

typedef struct oe_region_context oe_region_context_t;

/**
 * Adds new memory regions.
 *
 * This is a weak no-op function in Open Enclave. The enclave application
 * may override this function with a strong version. The strong version
 * may add memory regions using the following functions.
 *
 *     - oe_region_start()
 *     - oe_region_add_page()
 *     - oe_region_end()
 *
 * For each region, the function should call **oe_region_start()**, followed
 * by one more invocations of **oe_region_add_page()** and then finalized by
 * calling **oe_region_end()**.
 *
 * @param[in] context the context parameter from **oe_add_regions()**
 * @param[in] vaddr the beginning virtual address of the region
 * @param[in] elf_image true if the region contains an ELF image
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER invalid parameter
 * @returns OE_FAILURE general failure.
 */
oe_result_t oe_region_add_regions(oe_region_context_t* context);

/**
 * Starts a new memory region.
 *
 * This function starts a new memory region. A memory region is a contiguous
 * set of pages within an enclave image. The region may contain an ELF image,
 * thread control structure, or binary data. This function adds a new entry to
 * the regions table, which keeps track of information about the region. This
 * table is accessible within the enclave. If the region is an ELF image, its
 * symbols are registered with the debugger.
 *
 * @param[in] context the context parameter from **oe_add_regions()**
 * @param[in] id an integer identifier for this region (caller defined)
 * @param[in] is_elf true if the region contains an ELF image
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER invalid parameter
 * @returns OE_FAILURE page add failed
 */
oe_result_t oe_region_start(
    oe_region_context_t* context,
    uint64_t id,
    bool is_elf);

/**
 * Ends a new memory region.
 *
 * This function ends a new memory region causing it to be added to the regions
 * table.
 *
 * @param[in] context the context parameter from **oe_add_regions()**
 * @param[in] region_size the size of the region in bytes
 * @param[in] elf_image true if the region contains an ELF image
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER invalid parameter
 * @returns OE_FAILURE page add failed
 */
oe_result_t oe_region_end(oe_region_context_t* context);

/**
 * Adds a new region page.
 *
 * This function adds a new page to a region within an SGX enclave image.
 * The **oe_region_start()** function must have been called beforehand.
 *
 * @param[in] context the context parameter from **oe_add_regions()**
 * @param[in] vaddr the virtual address of the page in the enclave image
 * @param[in] page the address of the page to be added
 * @param[in] flags the page creation flags, which must be one or more of:
 *                - SGX_SECINFO_R -- readable page
 *                - SGX_SECINFO_W -- writeable page
 *                - SGX_SECINFO_X -- executable page
 *                - SGX_SECINFO_TCS -- thread control structure page
 *                - SGX_SECINFO_REG -- regular page
 * @param[in] extend whether to extend (measure) the page contents
 *
 * @returns OE_OK
 * @returns OE_INVALID_PARAMETER invalid parameter
 * @returns OE_FAILURE page add failed
 */
oe_result_t oe_region_add_page(
    oe_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend);

/* Region structure */
typedef struct _oe_region
{
    uint64_t id;
    bool is_elf;
    uint64_t vaddr; /* virtual address of the region */
    uint64_t size;  /* is of the region in bytes */
} oe_region_t;

typedef struct _oe_sgx_load_context oe_sgx_load_context_t;

struct oe_region_context
{
    /* If false, then only determine the size of the regions */
    bool load;

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

OE_EXTERNC_END

#endif /* _OE_INTERNAL_REGION_H */
