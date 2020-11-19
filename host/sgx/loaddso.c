// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/dynlink.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include "../memalign.h"
#include "enclave.h"
#include "sgxload.h"

static oe_result_t _unload_image(oe_enclave_image_t* image)
{
    if (image)
    {
        oe_unload_enclave_dso(&image->dso_load_state);
        memset(image, 0, sizeof(*image));
    }
    return OE_OK;
}

static oe_result_t _calculate_size(
    const oe_enclave_image_t* image,
    size_t* image_size)
{
    *image_size = 0;
    for (dso_t* p = image->dso_load_state.head; p; p = p->next)
    {
        *image_size += oe_get_dso_size(p);
        *image_size += oe_get_dso_segments_size(p);
    }
    *image_size = oe_round_up_to_page_size(*image_size);

    return OE_OK;
}

static size_t _get_aligned_tls_size(const oe_enclave_image_t* image)
{
    uint64_t total_tls_size = 0;
    for (dso_t* p = image->dso_load_state.head; p; p = p->next)
        total_tls_size += p->tls.size;
    return oe_round_up_to_multiple(total_tls_size, OE_PAGE_SIZE);
}

static oe_result_t _get_tls_page_count(
    const oe_enclave_image_t* image,
    size_t* tls_page_count)
{
    *tls_page_count = _get_aligned_tls_size(image) / OE_PAGE_SIZE;
    return OE_OK;
}

/*
**==============================================================================
**
** Image layout:
**
**     NHEAP = number of heap pages
**     NSTACK = number of stack pages
**     NTCS = number of TCS objects
**     GUARD = an unmapped guard page
**
**     [PAGES]:
**         [PROGRAM-PAGES]
**         [HEAP-PAGE]*NHEAP
**         ( [GUARD] [STACK-PAGE]*NSTACK [TCS-PAGES]*1 ) * NTCS
**
**     [PROGRAM-PAGES]:
**         [CODE-PAGES]: flags=reg|x|r content=(ELF segment)
**         [DATA-PAGES]: flags=reg|w|r content=(ELF segment)
**
**     [DSO-PAGES]: flags=reg|w|r content=(packed DSO structs)
**
**     [HEAP-PAGES]: flags=reg|w|r content=0x00000000
**
**     [THREAD-PAGES]:
**         [GUARD-PAGE]
**         [STACK-PAGES]: flags=reg|w|r content=0xCCCCCCCC
**         [GUARD-PAGE]
**         [TCS-PAGE]
**         [SSA1-PAGE1]: flags=reg|w|r content=0x00000000 SSA-slot 0
**         [SSA2-PAGE2]: flags=reg|w|r content=0x00000000 SSA-slot 1
**         [GUARD-PAGE]
**         [SEG1-PAGE]: flags=reg|w|r content=0x00000000 FS or GS segment
**         [SEG2-PAGE]: flags=reg|w|r content=0x00000000 FS or GS segment
**
**==============================================================================
*/

static uint64_t _make_secinfo_flags(uint32_t flags)
{
    uint64_t r = 0;

    if (flags & PF_R)
        r |= SGX_SECINFO_R;

    if (flags & PF_W)
        r |= SGX_SECINFO_W;

    if (flags & PF_X)
        r |= SGX_SECINFO_X;

    return r;
}

static oe_result_t _add_dso_segment_pages(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr);
    uint64_t enclave_base = enclave->addr;
    uint64_t dso_rva = *vaddr;

    for (dso_t* p = image->dso_load_state.head; p; p = p->next)
    {
        for (size_t i = 0; i < p->loadmap->nsegs; i++)
        {
            loadseg_t* seg = &p->loadmap->segs[i];

            uint64_t page_rva = oe_round_down_to_page_size(seg->p_vaddr);
            uint64_t segment_end = seg->p_vaddr + seg->p_memsz;
            uint64_t flags = _make_secinfo_flags(seg->p_flags);
            if (flags == 0)
            {
                OE_RAISE_MSG(
                    OE_UNEXPECTED, "Segment with no page protections found.");
            }
            flags |= SGX_SECINFO_REG;

            for (; page_rva < segment_end; page_rva += OE_PAGE_SIZE)
            {
                OE_CHECK(oe_sgx_load_enclave_data(
                    context,
                    enclave_base,
                    enclave_base + dso_rva + page_rva,
                    (uint64_t)p->map + page_rva,
                    flags,
                    true));
            }
        }
        p->seg_rva = dso_rva;
        dso_rva += p->map_len;
    }

    *vaddr = dso_rva;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_dso_pages(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr);

    uint64_t enclave_base = enclave->addr;
    uint64_t offset = 0;
    uint64_t prev_offset = OE_UINT64_MAX;
    uint64_t next_offset = OE_UINT64_MAX;

    /* Size and allocate the staging memory pages for DSO structures */
    size_t dso_data_size = 0;
    for (dso_t* p = image->dso_load_state.head; p; p = p->next)
        dso_data_size += oe_get_dso_size(p);
    dso_data_size = oe_round_up_to_page_size(dso_data_size);
    uint8_t* dso_map = oe_memalign(OE_PAGE_SIZE, dso_data_size);
    if (!dso_map)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Stage the dso_t structs and replace pointers with RVA based on the
     * enclave base so that the pointers can be marshelled into the enclave
     * without breaking the enclave measurement. */
    for (dso_t* p = image->dso_load_state.head; p; p = p->next)
    {
        dso_ref_t p_ref = {0};
        p_ref.prev_rva = prev_offset;
        prev_offset = offset;
        p_ref.self_rva = offset;
        p->self_rva = offset;
        p_ref.seg_rva = p->seg_rva;
        p_ref.dyn_rva = (uint64_t)p->dynv - (uint64_t)p->base;

        p_ref.phdr_rva = (uint64_t)(p->phdr) - (uint64_t)p->base;
        p_ref.phnum = p->phnum;

        p_ref.tls_id = p->tls_id;
        p_ref.tls = p->tls;
        p_ref.tls.image =
            (void*)(p->tls.image ? (uint64_t)p->tls.image - (uint64_t)p->base : OE_UINT64_MAX);

        // Note that p_ref.base is left unpopulated, as it will be calculated
        // from p_ref.seg_rva inside the enclave anyway.

        OE_CHECK(oe_memcpy_s(
            dso_map + offset, dso_data_size - offset, &p_ref, sizeof(p_ref)));
        offset += sizeof(p_ref);

        /* DSOs are copied into the enclave without the shortname/pathname
         * of the binary. Existing signing behavior expects that an enclave
         * binary named foo is equivalent to foo.signed, and writing the load
         * time path/shortname of the enclave will measure it and break this
         * behavior */
    }

    /* Do a reverse walk using prev to fix up all the remaining pointers
     * directly in the staged pages */
    for (dso_t* p = image->dso_load_state.tail; p; p = p->prev)
    {
        dso_ref_t* p_ref = (dso_ref_t*)(dso_map + p->self_rva);
        p_ref->needed_by_rva =
            p->needed_by ? p->needed_by->self_rva : OE_UINT64_MAX;
        p_ref->next_rva = next_offset;
        next_offset = p->self_rva;
    }

    /* Explicitly zero the rest of the remaining page-aligned memory */
    if (dso_data_size > offset)
    {
        OE_CHECK(oe_memset_s(
            dso_map + offset,
            dso_data_size - offset,
            0,
            dso_data_size - offset));
    }

    /* Add the patched dso_t pages into the enclave */
    {
        const oe_page_t* pages = (const oe_page_t*)dso_map;
        size_t npages = dso_data_size / sizeof(oe_page_t);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclave_base + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave_base, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    oe_memalign_free(dso_map);
    return result;
}

static oe_result_t _add_pages(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_CHECK(_add_dso_segment_pages(image, context, enclave, vaddr));
    OE_CHECK(_add_dso_pages(image, context, enclave, vaddr));
    result = OE_OK;
done:
    return result;
}

static oe_result_t _get_dso_sym_rva(dso_t* dso, const char* name, uint64_t* rva)
{
    oe_result_t result = OE_UNEXPECTED;
    symdef_t def = {0};

    if (!dso || !name || !rva)
        OE_RAISE(OE_INVALID_PARAMETER);

    def = find_sym(dso, name, 1);
    if (!def.sym)
        OE_RAISE(OE_NOT_FOUND);

    *rva = def.sym->st_value;
    result = OE_OK;
done:
    return result;
}

static oe_result_t _set_uint64_t_dso_sym_value(
    dso_t* dso,
    const char* name,
    uint64_t value)
{
    oe_result_t result = OE_UNEXPECTED;

    symdef_t def = find_sym(dso, name, 1);
    if (!def.sym)
        OE_RAISE(OE_NOT_FOUND);

    uint64_t* symbol_address = (uint64_t*)(dso->map + def.sym->st_value);
    *symbol_address = value;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch(oe_enclave_image_t* image, size_t enclave_size)
{
    oe_result_t result = OE_UNEXPECTED;
    dso_t* head = image->dso_load_state.head;
    uint64_t enclave_rva = 0;
    uint64_t dso_head_rva = 0;
    size_t dso_data_size = 0;
    oe_sgx_enclave_properties_t* oeprops =
        (oe_sgx_enclave_properties_t*)(head->map + head->oeinfo_rva);

    assert((head->map_len & (OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_size & (OE_PAGE_SIZE - 1)) == 0);

    /* NOTE: This implementation drops the zeroing of the ELF header
     * e_shoff, e_shnum, and e_shstrndx fields. It's not clear why that was
     * necessary in the original implementation. */

    oeprops->image_info.enclave_size = enclave_size;
    oeprops->image_info.oeinfo_rva = head->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Set _enclave_rva to its own rva offset*/
    OE_CHECK(_get_dso_sym_rva(head, "_enclave_rva", &enclave_rva));
    OE_CHECK(_set_uint64_t_dso_sym_value(head, "_enclave_rva", enclave_rva));

    /* Get the total size of all segments */
    image->dso_load_state.segments_size = 0;
    for (dso_t* p = head; p; p = p->next)
        image->dso_load_state.segments_size += oe_get_dso_segments_size(p);

    /* The dso_t structs are laid out right after the program segments.
     * Note that OE currently always loads the program segments at offset 0
     * relative to the enclave base */
    dso_head_rva = image->dso_load_state.segments_size;

    for (dso_t* p = head; p; p = p->next)
        dso_data_size += oe_get_dso_size(p);
    dso_data_size = oe_round_up_to_page_size(dso_data_size);

    OE_CHECK(_set_uint64_t_dso_sym_value(head, "_dso_head_rva", dso_head_rva));
    OE_CHECK(
        _set_uint64_t_dso_sym_value(head, "_dso_data_size", dso_data_size));

    /* The heap is right after all the list of DSO structs */
    oeprops->image_info.heap_rva = dso_head_rva + dso_data_size;

    /* Zero the sigstruct so it is not part of the enclave measurement */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    /* Fixup the TD offset based on the total static TLS allocation */
    uint64_t aligned_total_tls_size = _get_aligned_tls_size(image);
    _set_uint64_t_dso_sym_value(
        head,
        "_td_from_tcs_offset",
        aligned_total_tls_size + OE_SGX_TCS_CONTROL_PAGES * OE_PAGE_SIZE);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_load_enclave_properties(
    const oe_enclave_image_t* image,
    oe_sgx_enclave_properties_t* properties)
{
    dso_t* head = image->dso_load_state.head;
    return oe_memcpy_s(
        properties,
        sizeof(*properties),
        head->map + head->oeinfo_rva,
        sizeof(*properties));
}

static oe_result_t _sgx_update_enclave_properties(
    const oe_enclave_image_t* image,
    const oe_sgx_enclave_properties_t* properties)
{
    dso_t* head = image->dso_load_state.head;
    return oe_memcpy_s(
        head->map + head->oeinfo_rva,
        sizeof(*properties),
        properties,
        sizeof(*properties));
}

static oe_result_t _sgx_get_enclave_properties(
    const oe_enclave_image_t* image,
    oe_sgx_enclave_properties_t** properties,
    size_t* file_offset)
{
    oe_result_t result = OE_UNEXPECTED;
    dso_t* head = image->dso_load_state.head;
    if (!head || !head->oeinfo_file_pos)
        OE_RAISE_MSG(
            OE_NOT_FOUND,
            ".oeinfo section has not been loaded for the image",
            NULL);
    *properties = (oe_sgx_enclave_properties_t*)(head->map + head->oeinfo_rva);
    *file_offset = head->oeinfo_file_pos;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _get_debug_info(
    oe_enclave_image_t* image,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Get total number of modules to load */
    size_t dso_count = 0;
    for (dso_t* p = image->dso_load_state.head; p; p = p->next, dso_count++)
    {
    }
    enclave->num_debug_modules = dso_count;

    /* Allocate array for debug_modules information */
    enclave->debug_modules = (oe_debug_module_t*)calloc(
        1, enclave->num_debug_modules * sizeof(oe_debug_module_t));
    if (!enclave->debug_modules)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize each debug load module */
    uint32_t i = 0;
    for (dso_t* p = image->dso_load_state.head; p; p = p->next, i++)
    {
        enclave->debug_modules[i].magic = OE_DEBUG_MODULE_MAGIC;
        enclave->debug_modules[i].version = 1;
        enclave->debug_modules[i].base_address = enclave->addr + p->seg_rva;
        enclave->debug_modules[i].size = p->map_len;
        size_t path_length = strlen(p->name);
        enclave->debug_modules[i].path_length = path_length;
        enclave->debug_modules[i].path = malloc(path_length + 1);
        if (!enclave->debug_modules[i].path)
            OE_RAISE(OE_OUT_OF_MEMORY);
        strncpy(enclave->debug_modules[i].path, p->name, path_length + 1);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_load_elf_enclave_image(
    const char* path,
    oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    memset(image, 0, sizeof(oe_enclave_image_t));
    dso_t* dso = NULL;

    image->dso_load_state.tls_align = MIN_TLS_ALIGN;
    OE_CHECK(oe_load_enclave_dso(path, &image->dso_load_state, NULL, &dso));
    OE_CHECK(oe_load_deps(&image->dso_load_state, dso));

    /* NOTE: MUSL iterates through the linked list to add_syms() right after
     * load_deps(), but the values are only used during relocation in the
     * enclave, so OE defers updating those values until after the dso
     * structs are marshalled into the enclave to avoid an extra RVA to
     * virtual address translation. */

    image->type = OE_IMAGE_TYPE_ELF;
    image->calculate_size = _calculate_size;
    image->get_tls_page_count = _get_tls_page_count;
    image->add_pages = _add_pages;
    image->sgx_patch = _patch;
    image->sgx_load_enclave_properties = _sgx_load_enclave_properties;
    image->sgx_update_enclave_properties = _sgx_update_enclave_properties;
    image->sgx_get_enclave_properties = _sgx_get_enclave_properties;
    image->unload = _unload_image;
    image->get_debug_info = _get_debug_info;

    result = OE_OK;

done:

    if (OE_OK != result)
        _unload_image(image);

    return result;
}
