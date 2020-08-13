// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include <string.h>
#include "../memalign.h"
#include "../strings.h"
#include "enclave.h"
#include "sgxload.h"

static oe_result_t _free_elf_image(oe_enclave_image_t* image)
{
    if (image->u.elf.elf.data)
    {
        free(image->u.elf.elf.data);
    }

    if (image->image_base)
    {
        oe_memalign_free(image->image_base);
    }

    if (image->u.elf.segments)
    {
        oe_memalign_free(image->u.elf.segments);
    }

    memset(image, 0, sizeof(*image));

    return OE_OK;
}

static oe_result_t _load_elf_image(const char* path, oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;
    const elf64_ehdr_t* eh;
    size_t pt_load_segments_index;
    bool has_build_id = false;
    size_t segments_size = 0;

    assert(image && path);

    memset(image, 0, sizeof(*image));

    if (elf64_load(path, &image->u.elf.elf) != 0)
    {
        OE_RAISE(OE_INVALID_IMAGE);
    }

    /* Save pointer to header for convenience */
    eh = (elf64_ehdr_t*)image->u.elf.elf.data;

    /* Fail if not PIE or shared object */
    if (eh->e_type != ET_DYN)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "elf image is not a PIE or shared object", NULL);

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "elf image is not Intel X86 64-bit", NULL);

    /* Save entry point address */
    image->entry_rva = eh->e_entry;

    /* Scan through the section headers and extract the following values from
     * these sections.
     *   .text: text_rva
     *   .oeinfo: oeinfo_rva, oeinfo_file_pos
     *   .note.gnu.build-id: has_build_id
     *   .tdata: tdata_rva, tdata_size, tdata_align
     *   .tbss: tbss_size, tbss_align
     */
    {
        for (i = 0; i < eh->e_shnum; i++)
        {
            const elf64_shdr_t* sh =
                elf64_get_section_header(&image->u.elf.elf, i);

            /* Invalid section header. The elf file is corrupted. */
            if (sh == NULL)
                OE_RAISE(OE_INVALID_IMAGE);

            const char* name =
                elf64_get_string_from_shstrtab(&image->u.elf.elf, sh->sh_name);

            if (name)
            {
                if (strcmp(name, ".text") == 0)
                {
                    image->text_rva = sh->sh_addr;
                }
                else if (strcmp(name, ".oeinfo") == 0)
                {
                    image->oeinfo_rva = sh->sh_addr;
                    image->oeinfo_file_pos = sh->sh_offset;
                    OE_TRACE_VERBOSE(
                        "Found properties block offset %lx size %lx",
                        sh->sh_offset,
                        sh->sh_size);
                }

                else if (strcmp(name, ".note.gnu.build-id") == 0)
                {
                    has_build_id = true;
                }
                else if (strcmp(name, ".tdata") == 0)
                {
                    // These items must match program header values.
                    image->tdata_rva = sh->sh_addr;
                    image->tdata_size = sh->sh_size;
                    image->tdata_align = sh->sh_addralign;

                    OE_TRACE_VERBOSE(
                        "loadelf: tdata { rva=%lx, size=%lx, align=%ld }\n",
                        sh->sh_addr,
                        sh->sh_size,
                        sh->sh_addralign);
                }
                else if (strcmp(name, ".tbss") == 0)
                {
                    image->tbss_size = sh->sh_size;
                    image->tbss_align = sh->sh_addralign;
                    OE_TRACE_VERBOSE(
                        "loadelf: tbss { size=%ld, align=%ld }\n",
                        sh->sh_size,
                        sh->sh_addralign);
                }
            }
        }

        /* Fail if required sections not found */
        if ((0 == image->text_rva) || (0 == image->oeinfo_rva))
        {
            OE_RAISE(OE_INVALID_IMAGE);
        }

        /* It is now the default for linux shared libraries and executables to
         * have the build-id note. GCC by default passes the --build-id option
         * to linker, whereas clang does not. Build-id is also used as a key by
         * debug symbol-servers. If no build-id is found emit a trace message.
         * */
        if (!has_build_id)
        {
            OE_TRACE_ERROR("loadelf: enclave image does not have build-id.\n");
        }
    }

    /* Find out the image size and number of segments to be loaded */
    {
        uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
        uint64_t hi = 0;                  /* highest address of all segments */

        for (i = 0; i < eh->e_phnum; i++)
        {
            const elf64_phdr_t* ph =
                elf64_get_program_header(&image->u.elf.elf, i);

            /* Check for corrupted program header. */
            if (ph == NULL)
                OE_RAISE(OE_INVALID_IMAGE);

            /* Check for proper sizes for the program segment. */
            if (ph->p_filesz > ph->p_memsz)
                OE_RAISE(OE_INVALID_IMAGE);

            switch (ph->p_type)
            {
                case PT_LOAD:
                    if (lo > ph->p_vaddr)
                        lo = ph->p_vaddr;

                    if (hi < ph->p_vaddr + ph->p_memsz)
                        hi = ph->p_vaddr + ph->p_memsz;

                    image->u.elf.num_segments++;
                    break;

                default:
                    break;
            }
        }

        /* Fail if LO not found */
        if (lo != 0)
            OE_RAISE(OE_INVALID_IMAGE);

        /* Fail if HI not found */
        if (hi == 0)
            OE_RAISE(OE_INVALID_IMAGE);

        /* Fail if no segment found */
        if (image->u.elf.num_segments == 0)
            OE_RAISE(OE_INVALID_IMAGE);

        /* Calculate the full size of the image (rounded up to the page size) */
        image->image_size = oe_round_up_to_page_size(hi - lo);
    }

    /* Allocate segments */
    segments_size = image->u.elf.num_segments * sizeof(oe_elf_segment_t);
    image->u.elf.segments =
        (oe_elf_segment_t*)oe_memalign(OE_PAGE_SIZE, segments_size);
    memset(image->u.elf.segments, 0, segments_size);
    if (!image->u.elf.segments)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Allocate image on a page boundary */
    image->image_base = (char*)oe_memalign(OE_PAGE_SIZE, image->image_size);
    if (!image->image_base)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Clear the image memory */
    memset(image->image_base, 0, image->image_size);

    /* Add all loadable program segments to SEGMENTS array */
    for (i = 0, pt_load_segments_index = 0; i < eh->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&image->u.elf.elf, i);
        oe_elf_segment_t* seg = &image->u.elf.segments[pt_load_segments_index];
        void* segdata;

        assert(ph);
        assert(ph->p_filesz <= ph->p_memsz);

        switch (ph->p_type)
        {
            case PT_LOAD:
            {
                /* Cache the segment properties used during the image load */
                seg->memsz = ph->p_memsz;
                seg->vaddr = ph->p_vaddr;

                /* Map the segment permission flags to OE equivalents */
                {
                    if (ph->p_flags & PF_R)
                        seg->flags |= OE_SEGMENT_FLAG_READ;

                    if (ph->p_flags & PF_W)
                        seg->flags |= OE_SEGMENT_FLAG_WRITE;

                    if (ph->p_flags & PF_X)
                        seg->flags |= OE_SEGMENT_FLAG_EXEC;
                }

                segdata = elf64_get_segment(&image->u.elf.elf, i);
                if (!segdata)
                {
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        "loadelf: failed to get segment at index %lu\n",
                        i);
                }

                /* Copy the segment to the image */
                memcpy(image->image_base + seg->vaddr, segdata, ph->p_filesz);
                pt_load_segments_index++;
                break;
            }
            case PT_TLS:
            {
                // The ELF Handling for ELF Storage spec
                // (https://uclibc.org/docs/tls.pdf) says in page 4:
                //     "The section header is not usable; instead a new program
                //      header entry is created."
                // These assertions exist to understand those scenarios better.
                // Currently, in all cases except one, the section and program
                // header values are observed to be same.
                if (image->tdata_rva != ph->p_vaddr)
                {
                    if (image->tdata_rva == 0)
                    {
                        // The ELF has no thread local variables that are
                        // explicitly initialized. Therefore there is no .tdata
                        // section; only a .tbss section.
                        //
                        // In this case, the linker seems to put the address of
                        // the .tbss section in p_vaddr field; however it leaves
                        // the size zero. This seems to be strange linker
                        // behavior; we don't assert on it.
                        OE_TRACE_INFO(
                            "Ignoring .tdata_rva, p_vaddr mismatch for "
                            "empty .tdata section");
                    }
                    else
                    {
                        OE_TRACE_ERROR(
                            "loadelf: .tdata rva mismatch. Section value = "
                            "%lx, "
                            "Program header value = 0x%lx\n",
                            image->tdata_rva,
                            ph->p_vaddr);
                        OE_RAISE(OE_INVALID_IMAGE);
                    }
                }
                if (image->tdata_size != ph->p_filesz)
                {
                    // Always assert on size mismatch.
                    OE_TRACE_ERROR(
                        "loadelf: .tdata_size mismatch. Section value = %lx, "
                        "Program "
                        "header value = 0x%lx\n",
                        image->tdata_size,
                        ph->p_filesz);
                    OE_RAISE(OE_INVALID_IMAGE);
                }
                break;
            }
            default:
                /* Ignore all other segment types */
                break;
        }
    }

    assert(pt_load_segments_index == image->u.elf.num_segments);

    /* check that segments are valid */
    for (i = 0; i < image->u.elf.num_segments - 1; i++)
    {
        const oe_elf_segment_t* seg = &image->u.elf.segments[i];
        const oe_elf_segment_t* seg_next = &image->u.elf.segments[i + 1];
        if (seg->vaddr >= seg_next->vaddr)
        {
            OE_RAISE_MSG(
                OE_UNEXPECTED,
                "loadelf: segment vaddrs found out of order\n",
                NULL);
        }
        if ((seg->vaddr + seg->memsz) >
            oe_round_down_to_page_size(seg_next->vaddr))
        {
            OE_RAISE(OE_OUT_OF_BOUNDS);
        }
    }

    image->u.elf.elf.magic = ELF_MAGIC;
    result = OE_OK;

done:

    if (result != OE_OK)
    {
        _free_elf_image(image);
    }
    return result;
}

OE_INLINE void _dump_relocations(const void* data, size_t size)
{
    const elf64_rela_t* p = (const elf64_rela_t*)data;
    size_t n = size / sizeof(elf64_rela_t);

    printf("=== Relocations:\n");

    for (size_t i = 0; i < n; i++, p++)
    {
        if (p->r_offset == 0)
            break;

        printf(
            "offset=%llu addend=%lld\n",
            OE_LLU(p->r_offset),
            OE_LLD(p->r_addend));
    }
}

static oe_result_t _calculate_size(
    const oe_enclave_image_t* image,
    size_t* image_size)
{
    *image_size = image->image_size + image->reloc_size;
    return OE_OK;
}

static oe_result_t _unload(oe_enclave_image_t* image)
{
    if (image->u.elf.reloc_data)
    {
        oe_memalign_free(image->u.elf.reloc_data);
    }

    return _free_elf_image(image);
}

// ------------------------------------------------------------------

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
**     [RELOCATION-PAGES]:
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

    if (flags & OE_SEGMENT_FLAG_READ)
        r |= SGX_SECINFO_R;

    if (flags & OE_SEGMENT_FLAG_WRITE)
        r |= SGX_SECINFO_W;

    if (flags & OE_SEGMENT_FLAG_EXEC)
        r |= SGX_SECINFO_X;

    return r;
}

static oe_result_t _add_relocation_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    const void* reloc_data,
    const size_t reloc_size,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (reloc_data && reloc_size)
    {
        const oe_page_t* pages = (const oe_page_t*)reloc_data;
        size_t npages = reloc_size / sizeof(oe_page_t);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclave_addr + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave_addr, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_segment_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    const oe_elf_segment_t* segment,
    void* image)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t flags;
    uint64_t page_rva;
    uint64_t segment_end;

    assert(context);
    assert(segment);
    assert(image);

    /* Take into account that segment base address may not be page aligned */
    page_rva = oe_round_down_to_page_size(segment->vaddr);
    segment_end = segment->vaddr + segment->memsz;
    flags = _make_secinfo_flags(segment->flags);

    if (flags == 0)
    {
        OE_RAISE_MSG(
            OE_UNEXPECTED, "Segment with no page protections found.\n", NULL);
    }

    flags |= SGX_SECINFO_REG;

    for (; page_rva < segment_end; page_rva += OE_PAGE_SIZE)
    {
        OE_CHECK(oe_sgx_load_enclave_data(
            context,
            enclave_addr,
            enclave_addr + page_rva,
            (uint64_t)image + page_rva,
            flags,
            true));
    }

    result = OE_OK;

done:
    return result;
}

/* Add image to enclave */
static oe_result_t _add_pages(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr && (*vaddr == 0));
    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert(enclave->size > image->image_size);

    /* Add the program segments first */
    for (i = 0; i < image->u.elf.num_segments; i++)
    {
        OE_CHECK(_add_segment_pages(
            context,
            enclave->addr,
            &image->u.elf.segments[i],
            image->image_base));
    }

    *vaddr = image->image_size;

    /* Add the relocation pages (contain relocation entries) */
    OE_CHECK(_add_relocation_pages(
        context,
        enclave->addr,
        image->u.elf.reloc_data,
        image->reloc_size,
        vaddr));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_dynamic_symbol_rva(
    oe_enclave_image_t* image,
    const char* name,
    uint64_t* rva)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};

    if (!image || !name || !rva)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (elf64_find_dynamic_symbol_by_name(&image->u.elf.elf, name, &sym) != 0)
        goto done;

    *rva = sym.st_value;
    result = OE_OK;
done:
    return result;
}

static oe_result_t _set_uint64_t_dynamic_symbol_value(
    oe_enclave_image_t* image,
    const char* name,
    uint64_t value)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};
    uint64_t* symbol_address = NULL;

    if (elf64_find_dynamic_symbol_by_name(&image->u.elf.elf, name, &sym) != 0)
        goto done;

    symbol_address = (uint64_t*)(image->image_base + sym.st_value);
    *symbol_address = value;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch(
    oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    size_t enclave_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_enclave_properties_t* oeprops;
    size_t i;
    uint64_t enclave_rva = 0;
    uint64_t aligned_size = 0;

    oeprops =
        (oe_sgx_enclave_properties_t*)(image->image_base + image->oeinfo_rva);

    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((image->reloc_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_size & (OE_PAGE_SIZE - 1)) == 0);

    /* Clear certain ELF header fields */
    for (i = 0; i < image->u.elf.num_segments; i++)
    {
        const oe_elf_segment_t* seg = &image->u.elf.segments[i];
        elf64_ehdr_t* ehdr = (elf64_ehdr_t*)(image->image_base + seg->vaddr);

        if (elf64_test_header(ehdr) == 0)
        {
            ehdr->e_shoff = 0;
            ehdr->e_shnum = 0;
            ehdr->e_shstrndx = 0;
            break;
        }
    }

    oeprops->image_info.enclave_size = enclave_size;
    oeprops->image_info.oeinfo_rva = image->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Set _enclave_rva to its own rva offset*/
    OE_CHECK(_get_dynamic_symbol_rva(image, "_enclave_rva", &enclave_rva));
    OE_CHECK(
        _set_uint64_t_dynamic_symbol_value(image, "_enclave_rva", enclave_rva));

    /* reloc right after image */
    oeprops->image_info.reloc_rva = image->image_size;
    oeprops->image_info.reloc_size = image->reloc_size;
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_rva", image->image_size));
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_size", image->reloc_size));

    /* heap right after image */
    oeprops->image_info.heap_rva = image->image_size + image->reloc_size;

    if (image->tdata_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_rva", image->tdata_rva);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_size", image->tdata_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_align", image->tdata_align);

        aligned_size +=
            oe_round_up_to_multiple(image->tdata_size, image->tdata_align);
    }
    if (image->tbss_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_size", image->tbss_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_align", image->tbss_align);

        aligned_size +=
            oe_round_up_to_multiple(image->tbss_size, image->tbss_align);
    }

    aligned_size = oe_round_up_to_multiple(aligned_size, OE_PAGE_SIZE);
    _set_uint64_t_dynamic_symbol_value(
        image,
        "td_from_tcs_offset",
        aligned_size + OE_SGX_NUM_CONTROL_PAGES * OE_PAGE_SIZE);
    context->num_tls_pages = aligned_size / OE_PAGE_SIZE;

    /* Clear the hash when taking the measure */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    result = OE_OK;
done:
    return result;
}

static oe_result_t _sgx_load_enclave_properties(
    const oe_enclave_image_t* image,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(section_name);

    /* Copy from the image at oeinfo_rva. */
    OE_CHECK(oe_memcpy_s(
        properties,
        sizeof(*properties),
        image->image_base + image->oeinfo_rva,
        sizeof(*properties)));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_update_enclave_properties(
    const oe_enclave_image_t* image,
    const char* section_name,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(section_name);

    /* Copy to both the image and ELF file*/
    OE_CHECK(oe_memcpy_s(
        (uint8_t*)image->u.elf.elf.data + image->oeinfo_file_pos,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

    OE_CHECK(oe_memcpy_s(
        image->image_base + image->oeinfo_rva,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

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

    /* Load the program segments into memory */
    OE_CHECK(_load_elf_image(path, image));

    /* Load the relocations into memory (zero-padded to next page size) */
    if (elf64_load_relocations(
            &image->u.elf.elf, &image->u.elf.reloc_data, &image->reloc_size) !=
        0)
        OE_RAISE(OE_INVALID_IMAGE);

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
        _dump_relocations(image->u.elf.reloc_data, image->reloc_size);

    image->type = OE_IMAGE_TYPE_ELF;
    image->calculate_size = _calculate_size;
    image->add_pages = _add_pages;
    image->sgx_patch = _patch;
    image->sgx_load_enclave_properties = _sgx_load_enclave_properties;
    image->sgx_update_enclave_properties = _sgx_update_enclave_properties;
    image->unload = _unload;

    result = OE_OK;

done:

    if (OE_OK != result)
        _unload(image);

    return result;
}
