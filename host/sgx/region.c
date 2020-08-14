#include "region.h"
#include <openenclave/bits/sgx/region.h>
#include <openenclave/internal/raise.h>
#include "sgxload.h"

static bool _valid_context(oe_region_context_t* context)
{
    if (!context || (context->sgx_load_context && !context->enclave_addr))
        return false;

    return true;
};

#if 0
/* This weak form may be overriden by the enclave application */
OE_WEAK
oe_result_t oe_region_add_regions(oe_region_context_t* context)
{
    (void)context;
    return OE_OK;
}
#endif

oe_result_t oe_region_start(
    oe_region_context_t* context,
    uint64_t id,
    bool is_elf)
{
    oe_result_t result = OE_OK;
    oe_region_t* region;

    if (!_valid_context(context) || id == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->num_regions == OE_MAX_REGIONS)
        OE_RAISE(OE_FAILURE);

    region = &context->regions[context->num_regions];
    region->id = id;
    region->is_elf = is_elf;
    region->vaddr = context->vaddr;

done:
    return result;
}

oe_result_t oe_region_end(oe_region_context_t* context)
{
    oe_result_t result = OE_OK;
    oe_region_t* region;

    if (!_valid_context(context))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->num_regions == OE_MAX_REGIONS)
        OE_RAISE(OE_FAILURE);

    region = &context->regions[context->num_regions];
    region->size = context->vaddr - region->vaddr;
    context->num_regions++;

done:
    return result;
}

oe_result_t oe_region_add_page(
    oe_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend)
{
    oe_result_t result = OE_OK;
    const oe_region_t* region;

    if (!_valid_context(context) || !page)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->num_regions == OE_MAX_REGIONS)
        OE_RAISE(OE_FAILURE);

    region = &context->regions[context->num_regions];

    if (vaddr < region->vaddr)
        OE_RAISE(OE_FAILURE);

    if (context->sgx_load_context)
    {
        OE_CHECK(oe_sgx_load_enclave_data(
            context->sgx_load_context,
            context->enclave_addr,
            context->enclave_addr + vaddr,
            (uint64_t)page,
            flags,
            extend));
    }

    context->vaddr = vaddr + OE_PAGE_SIZE;

done:
    return result;
}
