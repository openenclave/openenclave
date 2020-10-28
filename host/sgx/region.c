#include <errno.h>
#include <sys/mman.h>
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

oe_result_t oe_region_start(
    oe_region_context_t* context,
    uint64_t id,
    bool is_elf,
    const char* path)
{
    oe_result_t result = OE_OK;
    oe_region_t* region;

    if (!_valid_context(context) || id == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->num_regions == OE_MAX_REGIONS)
        OE_RAISE(OE_FAILURE);

    if (path && !(context->path = realpath(path, NULL)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    region = &context->regions[context->num_regions];
    region->id = id;
    region->is_elf = is_elf;
    region->vaddr = context->vaddr;

done:
    return result;
}

static void _add_debug_image(
    oe_region_context_t* context,
    char* path,
    oe_region_t* region)
{
    oe_debug_image_t di;

    di.magic = OE_DEBUG_IMAGE_MAGIC;
    di.version = 1;
    di.path = path;
    di.path_length = strlen(di.path);
    di.base_address = context->enclave_addr + region->vaddr;
    di.size = region->size;
    context->debug_images[context->num_debug_images++] = di;
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

    if (context->path && region->is_elf)
    {
        _add_debug_image(context, context->path, region);
        context->path = NULL;
    }

done:

    if (context && context->path)
    {
        free(context->path);
        context->path = NULL;
    }

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

oe_result_t oe_region_debug_notify_loaded(oe_region_context_t* context)
{
    oe_result_t result = OE_OK;

    if (!_valid_context(context))
        OE_RAISE(OE_INVALID_PARAMETER);

    for (size_t i = 0; i < context->num_debug_images; ++i)
        oe_debug_notify_image_loaded(&context->debug_images[i]);

done:

    return result;
}

oe_result_t oe_region_debug_notify_unloaded(oe_region_context_t* context)
{
    oe_result_t result = OE_OK;

    if (!_valid_context(context))
        OE_RAISE(OE_INVALID_PARAMETER);

    for (size_t i = 0; i < context->num_debug_images; ++i)
        oe_debug_notify_image_unloaded(&context->debug_images[i]);

done:

    return result;
}
