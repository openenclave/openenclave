#define OE_TRACE_LEVEL 1
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <openenclave.h>
#include <oeinternal/utils.h>
#include <oeinternal/load.h>
#include <oeinternal/elf.h>

extern void *memalign(size_t alignment, size_t size);

OE_Result __OE_LoadSegments(
    const char* path,
    OE_Segment segments[OE_MAX_SEGMENTS],
    size_t* nsegments,
    uint64_t* entryaddr,
    uint64_t* textaddr)
{
    OE_Result result = OE_UNEXPECTED;
    Elf64 elf = ELF64_INIT;
    size_t i;
    const Elf64_Ehdr* eh;

    if (nsegments)
        *nsegments = 0;

    if (entryaddr)
        *entryaddr = 0;

    if (textaddr)
        *textaddr = 0;

    /* Check for null parameters */
    if (!path || !segments || !nsegments || !entryaddr || !textaddr)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Load the ELF-64 object */
    if (Elf64_Load(path, &elf) != 0)
        OE_THROW(OE_FAILURE);

    /* Save pointer to header for convenience */
    eh = elf.ehdr;

    /* Fail if not a dynamic object */
#if 0
    if (eh->e_type != ET_DYN)
        OE_THROW(OE_FAILURE);
#endif

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_THROW(OE_FAILURE);

    /* Fail if image is relocatable */
    if (eh->e_type == ET_REL)
        OE_THROW(OE_FAILURE);

    /* Save entry point address */
    *entryaddr = eh->e_entry;

    /* Find the address of the ".text" section */
    {
        for (i = 0; i < eh->e_shnum; i++)
        {
            const Elf64_Shdr* sh = &elf.shdrs[i];
            const char* name = Elf64_GetStringFromShstrtab(&elf, sh->sh_name);

            if (name && strcmp(name, ".text") == 0)
            {
                *textaddr = sh->sh_offset;
                break;
            }
        }

        /* If text section not found */
        if (i == eh->e_shnum)
            OE_THROW(OE_FAILURE);
    }

    /* Add all loadable program segments to SEGMENTS array */
    for (i = 0; i < eh->e_phnum; i++)
    {
        const Elf64_Phdr* ph = &elf.phdrs[i];
        OE_Segment seg;

        /* Skip non-loadable program segments */
        if (ph->p_type != PT_LOAD)
            continue;

        /* ATTN: handle PT_TLS (thread local storage) segments */
        if (ph->p_type == PT_TLS)
            OE_THROW(OE_UNIMPLEMENTED);

        /* Clear the segment */
        memset(&seg, 0, sizeof(OE_Segment));

        /* Set OE_Segment.memsz */
        seg.memsz = ph->p_memsz;

        /* Set OE_Segment.filesz */
        seg.filesz = ph->p_filesz;

        /* Set OE_Segment.offset */
        seg.offset = ph->p_offset;

        /* Set OE_Segment.vaddr */
        seg.vaddr = ph->p_vaddr;

        /* Set OE_Segment.flags */
        {
            if (ph->p_flags & PF_R) 
                seg.flags |= OE_SEGMENT_FLAG_READ;

            if (ph->p_flags & PF_W) 
                seg.flags |= OE_SEGMENT_FLAG_WRITE;

            if (ph->p_flags & PF_X) 
                seg.flags |= OE_SEGMENT_FLAG_EXEC;
        }

        /* Make a heap copy of this segment */
        if (elf.segments[i])
        {
            if (!(seg.filedata = malloc(seg.filesz)))
                OE_THROW(OE_OUT_OF_MEMORY);

            memcpy(seg.filedata, elf.segments[i], seg.filesz);
        }

        /* Check for array overflow */
        if (*nsegments == OE_MAX_SEGMENTS)
            OE_THROW(OE_FAILURE);

        /* Add to segments array */
        segments[(*nsegments)++] = seg;
    }

    /* If no segments found */
    if (*nsegments == 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

catch:

    if (result != OE_OK)
    {
        if (segments)
        {
            for (i = 0; i < *nsegments; i++)
            {
                OE_Segment* seg = &segments[i];
                free(seg->filedata);
            }

            *nsegments = 0;
        }
    }

    Elf64_Unload(&elf);

    return result;
}

OE_Result __OE_CalculateSegmentsSize(
    const OE_Segment* segments,
    size_t nsegments,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0; /* highest address of all segments */
    size_t i;

    if (size)
        *size = 0;

    /* Reject bad parameters */
    if (!segments || nsegments == 0 || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Cacluate boundaries (LO and HI) of the image */
    for (i = 0; i < nsegments; i++)
    {
        const OE_Segment* seg = &segments[i];

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
    *size = __OE_RoundUpToPageSize(hi - lo);

    result = OE_OK;

catch:

    return result;
}

OE_Result __OE_CombineSegments(
    const OE_Segment* segments,
    size_t nsegments,
    OE_Page** pages,
    size_t* npages)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0; /* highest address of all segments */
    size_t i;
    unsigned char* data = NULL;
    size_t size;

    if (pages)
        *pages = NULL;
        
    if (npages)
        *npages = 0;

    /* Reject bad parameters */
    if (!segments || nsegments == 0 || !pages || !npages)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Cacluate boundaries (LO and HI) of the image */
    {
        for (i = 0; i < nsegments; i++)
        {
            const OE_Segment* seg = &segments[i];

            if (seg->vaddr < lo)
                lo = seg->vaddr;

            if (seg->vaddr + seg->memsz > hi)
                hi = seg->vaddr + seg->memsz;
        }

        if (lo != 0)
            OE_THROW(OE_FAILURE);

        if (hi == 0)
            OE_THROW(OE_FAILURE);
    }

    /* Calculate the full size of the image (rounded up to the page size) */
    OE_TRY(__OE_CalculateSegmentsSize(segments, nsegments, &size));

    /* Allocate data on a page boundary */
    if (!(data = (unsigned char*)memalign(OE_PAGE_SIZE, size)))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Clear the image memory */
    memset(data, 0, size);

    /* Copy data from ELF file onto image memory */
    for (i = 0; i < nsegments; i++)
    {
        const OE_Segment* seg = &segments[i];
        memcpy(data + seg->vaddr, seg->filedata, seg->filesz);
    }

    *pages = (OE_Page*)data;
    *npages = size / OE_PAGE_SIZE;

    result = OE_OK;

catch:

    if (result != OE_OK)
        free(data);

    return result;
}
