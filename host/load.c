// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include <string.h>
#include "memalign.h"

oe_result_t __oe_load_segments(
    const char* path,
    oe_segment_t segments[OE_MAX_SEGMENTS],
    size_t* nsegments,
    uint64_t* entryaddr,
    uint64_t* textaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_t elf = ELF64_INIT;
    size_t i;
    const elf64_ehdr_t* eh;
    elf64_off_t oeinfo_offset = 0;
    elf64_xword_t oeinfo_size = 0;

    if (nsegments)
        *nsegments = 0;

    if (entryaddr)
        *entryaddr = 0;

    if (textaddr)
        *textaddr = 0;

    /* Check for null parameters */
    if (!path || !segments || !nsegments || !entryaddr || !textaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF-64 object */
    if (elf64_load(path, &elf) != 0)
        OE_RAISE(OE_FAILURE);

    /* Save pointer to header for convenience */
    eh = (elf64_ehdr_t*)elf.data;

/* Fail if not a dynamic object */
#if 0
    if (eh->e_type != ET_DYN)
        OE_THROW(OE_FAILURE);
#endif

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE(OE_FAILURE);

    /* Fail if image is relocatable */
    if (eh->e_type == ET_REL)
        OE_RAISE(OE_FAILURE);

    /* Save entry point address */
    *entryaddr = eh->e_entry;

    /* Find the addresses of the ".text" and ".oeinfo" sections */
    {
        for (i = 0; i < eh->e_shnum; i++)
        {
            const elf64_shdr_t* sh = elf64_get_section_header(&elf, i);

            /* Invalid section header. The elf file is corrupted. */
            if (sh == NULL)
                OE_RAISE(OE_FAILURE);

            const char* name =
                elf64_get_string_from_shstrtab(&elf, sh->sh_name);

            if (name && strcmp(name, ".text") == 0)
            {
                *textaddr = sh->sh_offset;
            }
            else if (name && strcmp(name, ".oeinfo") == 0)
            {
                oeinfo_offset = sh->sh_offset;
                oeinfo_size = sh->sh_size;
                OE_TRACE_INFO(
                    "Found properties block offset %lx size %lx",
                    oeinfo_offset,
                    oeinfo_size);
            }
        }

        /* If text section not found */
        if (*textaddr == 0)
            OE_RAISE(OE_FAILURE);
    }

    /* Add all loadable program segments to SEGMENTS array */
    for (i = 0; i < eh->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&elf, i);
        oe_segment_t seg;

        /* Check for corrupted program header. */
        if (ph == NULL)
            OE_RAISE(OE_FAILURE);

        /* Skip non-loadable program segments */
        if (ph->p_type != PT_LOAD)
            continue;

        /* Check for proper sizes for the program segment. */
        if (ph->p_filesz > ph->p_memsz)
            OE_RAISE(OE_FAILURE);

        /* ATTN: handle PT_TLS (thread local storage) segments */
        if (ph->p_type == PT_TLS)
            OE_RAISE(OE_UNSUPPORTED);

        /* Clear the segment */
        memset(&seg, 0, sizeof(oe_segment_t));

        /* Set oe_segment_t.memsz */
        seg.memsz = ph->p_memsz;

        /* Set oe_segment_t.filesz */
        seg.filesz = ph->p_filesz;

        /* Set oe_segment_t.offset */
        seg.offset = ph->p_offset;

        /* Set oe_segment_t.vaddr */
        seg.vaddr = ph->p_vaddr;

        /* Set oe_segment_t.flags */
        {
            if (ph->p_flags & PF_R)
                seg.flags |= OE_SEGMENT_FLAG_READ;

            if (ph->p_flags & PF_W)
                seg.flags |= OE_SEGMENT_FLAG_WRITE;

            if (ph->p_flags & PF_X)
                seg.flags |= OE_SEGMENT_FLAG_EXEC;
        }

        /* Make a heap copy of this segment */
        if (elf64_get_segment(&elf, i))
        {
            if (!(seg.filedata = malloc(seg.filesz)))
                OE_RAISE(OE_OUT_OF_MEMORY);

            OE_CHECK(
                oe_memcpy_s(
                    seg.filedata,
                    seg.filesz,
                    elf64_get_segment(&elf, i),
                    seg.filesz));

            /* Zero out the .oeinfo section if within this segment */
            if (oeinfo_size && (oeinfo_offset >= seg.offset) &&
                (oeinfo_offset <= seg.offset + seg.filesz))
            {
                /* Check the section doesn't cross the end of the segment */
                if ((oeinfo_offset + oeinfo_size) > (seg.offset + seg.filesz))
                    OE_RAISE(OE_OUT_OF_BOUNDS);

                memset( // All sizes/address calculations in bytes
                    ((char*)seg.filedata) + oeinfo_offset - seg.offset,
                    0,
                    oeinfo_size);
                OE_TRACE_INFO("Zeroed out properties block in segment %lu", i);
            }
        }

        /* Check for array overflow */
        if (*nsegments == OE_MAX_SEGMENTS)
            OE_RAISE(OE_FAILURE);

        /* Add to segments array */
        segments[(*nsegments)++] = seg;
    }

    /* If no segments found */
    if (*nsegments == 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
    {
        if (segments)
        {
            for (i = 0; i < *nsegments; i++)
            {
                oe_segment_t* seg = &segments[i];
                free(seg->filedata);
            }

            *nsegments = 0;
        }
    }

    elf64_unload(&elf);

    return result;
}

oe_result_t __oe_calculate_segments_size(
    const oe_segment_t* segments,
    size_t nsegments,
    size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0;                  /* highest address of all segments */
    size_t i;

    if (size)
        *size = 0;

    /* Reject bad parameters */
    if (!segments || nsegments == 0 || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Calculate boundaries (LO and HI) of the image */
    for (i = 0; i < nsegments; i++)
    {
        const oe_segment_t* seg = &segments[i];

        if (seg->vaddr < lo)
            lo = seg->vaddr;

        if (seg->vaddr + seg->memsz > hi)
            hi = seg->vaddr + seg->memsz;
    }

    /* Fail if LO not found */
    if (lo != 0)
        OE_THROW(OE_FAILURE);

    /* Fail if HI not found */
    if (hi == 0)
        OE_THROW(OE_FAILURE);

    /* Calculate the full size of the image (rounded up to the page size) */
    *size = __oe_round_up_to_page_size(hi - lo);

    result = OE_OK;

OE_CATCH:

    return result;
}

oe_result_t __oe_combine_segments(
    const oe_segment_t* segments,
    size_t nsegments,
    oe_page_t** pages,
    size_t* npages)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0;                  /* highest address of all segments */
    size_t i;
    unsigned char* data = NULL;
    size_t size;

    if (pages)
        *pages = NULL;

    if (npages)
        *npages = 0;

    /* Reject bad parameters */
    if (!segments || nsegments == 0 || !pages || !npages)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Calculate boundaries (LO and HI) of the image */
    {
        for (i = 0; i < nsegments; i++)
        {
            const oe_segment_t* seg = &segments[i];

            if (seg->vaddr < lo)
                lo = seg->vaddr;

            if (seg->vaddr + seg->memsz > hi)
                hi = seg->vaddr + seg->memsz;
        }

        if (lo != 0)
            OE_RAISE(OE_FAILURE);

        if (hi == 0)
            OE_RAISE(OE_FAILURE);
    }

    /* Calculate the full size of the image (rounded up to the page size) */
    OE_CHECK(__oe_calculate_segments_size(segments, nsegments, &size));

    /* Allocate data on a page boundary */
    if (!(data = (unsigned char*)oe_memalign(OE_PAGE_SIZE, size)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Clear the image memory */
    memset(data, 0, size);

    /* Copy data from ELF file onto image memory */
    for (i = 0; i < nsegments; i++)
    {
        const oe_segment_t* seg = &segments[i];
        OE_CHECK(
            oe_memcpy_s(
                data + seg->vaddr, seg->filesz, seg->filedata, seg->filesz));
    }

    *pages = (oe_page_t*)data;
    *npages = size / OE_PAGE_SIZE;

    result = OE_OK;

done:
    if (result != OE_OK)
        oe_memalign_free(data);

    return result;
}
