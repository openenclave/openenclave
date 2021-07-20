// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/module.h>
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
#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <io.h>
#define access _access
#define strdup _strdup
#define F_OK 0
#endif
#include "../memalign.h"
#include "../strings.h"
#include "enclave.h"
#include "sgxload.h"

static void _unload_elf_image(oe_enclave_elf_image_t* image)
{
    if (image)
    {
        if (image->elf.data)
            free(image->elf.data);

        if (image->path)
            free((void*)image->path);

        if (image->image_base)
            oe_memalign_free(image->image_base);

        if (image->segments)
            oe_memalign_free(image->segments);

        if (image->reloc_data)
            oe_memalign_free(image->reloc_data);

        memset(image, 0, sizeof(*image));
    }
}

static oe_result_t _unload_image(oe_enclave_image_t* image)
{
    if (image)
    {
        _unload_elf_image(&image->elf);
        if (image->submodule)
            _unload_elf_image(image->submodule);
        memset(image, 0, sizeof(*image));
    }
    return OE_OK;
}

/* Loads an ELF64 binary from disk into memory as image->elf.data
 * and provides a pointer to it as an ELF64 header structure.
 *
 * The caller is responsible for calling free on image->elf.data.
 */
static oe_result_t _read_elf_header(
    const char* path,
    oe_enclave_elf_image_t* image,
    elf64_ehdr_t** ehdr)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_ehdr_t* eh = NULL;

    /* Load the ELF64 into memory */
    if (elf64_load(path, &image->elf) != 0)
    {
        OE_RAISE(OE_INVALID_IMAGE);
    }
    eh = (elf64_ehdr_t*)image->elf.data;

    /* Fail if not PIE or shared object */
    if (eh->e_type != ET_DYN)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not a PIE or shared object", NULL);

    /* Fail if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not Intel X86 64-bit", NULL);

    /* Save entry point address needed to be set in the TCS for enclave app */
    image->entry_rva = eh->e_entry;

    *ehdr = eh;
    result = OE_OK;

done:
    return result;
}

/* Scan through the section headers to populate the following properties in the
 * image->elf struct:
 *   .oeinfo: oeinfo_rva, oeinfo_file_pos
 *   .tdata: tdata_rva, tdata_size, tdata_align
 *   .tbss: tbss_size, tbss_align
 *
 * Also checks for the presence of the .note.gnu.build-id which is needed for
 * the debugger contract.
 */
static oe_result_t _read_sections(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    bool has_build_id = false;

    for (size_t i = 0; i < ehdr->e_shnum; i++)
    {
        const elf64_shdr_t* sh = elf64_get_section_header(&image->elf, i);

        /* Invalid section header. The elf file is corrupted. */
        if (sh == NULL)
            OE_RAISE(OE_INVALID_IMAGE);

        const char* name =
            elf64_get_string_from_shstrtab(&image->elf, sh->sh_name);

        if (name)
        {
            if (strcmp(name, ".oeinfo") == 0)
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
                    "tdata { rva=%lx, size=%lx, align=%ld }",
                    sh->sh_addr,
                    sh->sh_size,
                    sh->sh_addralign);
            }
            else if (strcmp(name, ".tbss") == 0)
            {
                image->tbss_size = sh->sh_size;
                image->tbss_align = sh->sh_addralign;
                OE_TRACE_VERBOSE(
                    "tbss { size=%ld, align=%ld }",
                    sh->sh_size,
                    sh->sh_addralign);
            }
        }
    }

    /* It is now the default for linux shared libraries and executables to
     * have the build-id note. GCC by default passes the --build-id option
     * to linker, whereas clang does not. Build-id is also used as a key by
     * debug symbol-servers. If no build-id is found emit a trace message.
     * */
    if (!has_build_id)
    {
        OE_TRACE_ERROR("Enclave image does not have build-id.");
    }

    result = OE_OK;

done:
    return result;
}

/* Reads the number of loadable segments and allocates a zeroed, page-aligned
 * image buffer for reading the segment contents into.
 *
 * The caller is responsible for calling memalign_free on image->image_base.
 */
static oe_result_t _initialize_image_segments(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Find out the image size and number of segments to be loaded */
    uint64_t lo = 0xFFFFFFFFFFFFFFFF; /* lowest address of all segments */
    uint64_t hi = 0;                  /* highest address of all segments */

    for (size_t i = 0; i < ehdr->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&image->elf, i);

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

                image->num_segments++;
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
    if (image->num_segments == 0)
        OE_RAISE(OE_INVALID_IMAGE);

    /* Calculate the full size of the image (rounded up to the page size) */
    image->image_size = oe_round_up_to_page_size(hi - lo);

    /* Allocate the in-memory image for program segments on a page boundary */
    image->image_base = (char*)oe_memalign(OE_PAGE_SIZE, image->image_size);
    if (!image->image_base)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Zero initialize the in-memory image */
    memset(image->image_base, 0, image->image_size);

    result = OE_OK;

done:
    return result;
}

/* Populates the image buffer with the contents of all loadable segments.
 * For each loaded segment, this function caches the segment properties
 * needed during enclave load in image->segments.
 *
 * Also validates that the PT_TLS segment conforms to the enclave loader
 * expectations for handling TLS.
 *
 * The caller is responsible for calling memalign_free on image->segments.
 */
static oe_result_t _stage_image_segments(
    const elf64_ehdr_t* ehdr,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Allocate array of cached segment structures for enclave load */
    size_t segments_size = image->num_segments * sizeof(oe_elf_segment_t);
    image->segments =
        (oe_elf_segment_t*)oe_memalign(OE_PAGE_SIZE, segments_size);
    memset(image->segments, 0, segments_size);
    if (!image->segments)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Read all loadable program segments into in-memory image and cache their
     * properties in the segments array. */
    for (size_t i = 0, pt_read_segments_index = 0; i < ehdr->e_phnum; i++)
    {
        const elf64_phdr_t* ph = elf64_get_program_header(&image->elf, i);
        oe_elf_segment_t* segment = &image->segments[pt_read_segments_index];

        assert(ph);
        assert(ph->p_filesz <= ph->p_memsz);

        switch (ph->p_type)
        {
            case PT_LOAD:
            {
                /* Cache the segment properties for enclave page add */
                segment->memsz = ph->p_memsz;
                segment->vaddr = ph->p_vaddr;
                segment->flags = ph->p_flags;

                void* segment_data = elf64_get_segment(&image->elf, i);
                if (!segment_data)
                {
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        "Failed to get segment at index %lu",
                        i);
                }

                /* Copy the segment data to the image buffer */
                memcpy(
                    image->image_base + segment->vaddr,
                    segment_data,
                    ph->p_filesz);
                pt_read_segments_index++;
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
                        OE_RAISE_MSG(
                            OE_INVALID_IMAGE,
                            ".tdata rva mismatch. Section value = "
                            "%lx, Program header value = 0x%lx",
                            image->tdata_rva,
                            ph->p_vaddr);
                    }
                }
                if (image->tdata_size != ph->p_filesz)
                {
                    // Always assert on size mismatch.
                    OE_RAISE_MSG(
                        OE_INVALID_IMAGE,
                        ".tdata_size mismatch. Section value = %lx, "
                        "Program header value = 0x%lx",
                        image->tdata_size,
                        ph->p_filesz);
                }
                break;
            }
            default:
                /* Ignore all other segment types */
                break;
        }
    }

    /* Check that segments are valid */
    for (size_t i = 0; i < image->num_segments - 1; i++)
    {
        const oe_elf_segment_t* current = &image->segments[i];
        const oe_elf_segment_t* next = &image->segments[i + 1];
        if (current->vaddr >= next->vaddr)
        {
            OE_RAISE_MSG(
                OE_UNEXPECTED, "Segment vaddrs found out of order", NULL);
        }
        if ((current->vaddr + current->memsz) >
            oe_round_down_to_page_size(next->vaddr))
        {
            OE_RAISE_MSG(OE_INVALID_IMAGE, "Overlapping segments found", NULL);
        }
    }

    result = OE_OK;

done:
    return result;
}

OE_INLINE void _dump_relocations(const void* data, size_t size)
{
    const elf64_rela_t* p = (const elf64_rela_t*)data;
    size_t n = size / sizeof(elf64_rela_t);

    printf("=== Relocations:\n");

    for (size_t i = 0; i < n; i++, p++)
    {
        printf(
            "offset=%llu addend=%lld\n",
            OE_LLU(p->r_offset),
            OE_LLD(p->r_addend));
    }
}

/* Loads an ELF binary into memory and parses it for addition into the enclave
 * The caller is expected to have zeroed the output image memory buffer and is
 * responsible for calling _unload_elf_image on the resulting buffer when done.
 */
static oe_result_t _load_elf_image(
    const char* path,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_ehdr_t* ehdr = NULL;

    assert(image && path);

    OE_CHECK(_read_elf_header(path, image, &ehdr));

    OE_CHECK(_read_sections(ehdr, image));

    OE_CHECK(_initialize_image_segments(ehdr, image));

    OE_CHECK(_stage_image_segments(ehdr, image));

    /* Load the relocations into memory */
    if (elf64_load_relocations(
            &image->elf, &image->reloc_data, &image->reloc_size) != OE_OK)
        OE_RAISE(OE_INVALID_IMAGE);

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_VERBOSE)
        _dump_relocations(image->reloc_data, image->reloc_size);

    image->path = strdup(path);
    image->elf.magic = ELF_MAGIC;
    result = OE_OK;

done:
    if (result != OE_OK)
    {
        _unload_elf_image(image);
    }
    return result;
}

static oe_result_t _calculate_size(
    const oe_enclave_image_t* image,
    size_t* image_size)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Note that the image->elf.reloc_size holds the merged (base + module),
     * zero-padded relocation data. */
    OE_CHECK(oe_safe_add_sizet(
        image->elf.image_size, image->elf.reloc_size, image_size));
    if (image->submodule)
        OE_CHECK(oe_safe_add_sizet(
            *image_size, image->submodule->image_size, image_size));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_tls_page_count(
    const oe_enclave_image_t* image,
    size_t* tls_page_count)
{
    size_t tls_size = 0;

    if (image->elf.tdata_size)
    {
        tls_size += oe_round_up_to_multiple(
            image->elf.tdata_size, image->elf.tdata_align);
    }
    if (image->elf.tbss_size)
    {
        tls_size += oe_round_up_to_multiple(
            image->elf.tbss_size, image->elf.tbss_align);
    }

    tls_size = oe_round_up_to_multiple(tls_size, OE_PAGE_SIZE);

    *tls_page_count = tls_size / OE_PAGE_SIZE;
    return OE_OK;
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
**     *-annotated sections are added when a module is present
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
**     [*MODULE-PAGES]:
**         [*CODE-PAGES]: flags=reg|x|r content=(ELF segment)
**         [*DATA-PAGES]: flags=reg|w|r content=(ELF segment)
**
**     [RELOCATION-PAGES]:
**         [PROGRAM RELOCATION DATA]
**         [*MODULE RELOCATION DATA]
**         [ZERO PADDINGS]
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

static oe_result_t _add_relocation_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    const oe_enclave_elf_image_t* image,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (image->reloc_data && image->reloc_size)
    {
        const oe_page_t* pages = (const oe_page_t*)image->reloc_data;
        size_t npages = image->reloc_size / sizeof(oe_page_t);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclave->start_address + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave->base_address, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_segment_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    const oe_enclave_elf_image_t* image,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(context);
    assert(image);
    assert(vaddr);

    for (size_t i = 0; i < image->num_segments; i++)
    {
        oe_elf_segment_t* segment = &image->segments[i];

        /* Align if segment base address is not page aligned */
        uint64_t page_rva = oe_round_down_to_page_size(segment->vaddr);
        uint64_t segment_end = segment->vaddr + segment->memsz;
        uint64_t flags = _make_secinfo_flags(segment->flags);

        if (flags == 0)
        {
            OE_RAISE_MSG(
                OE_UNEXPECTED, "Segment with no page protections found.", NULL);
        }

        flags |= SGX_SECINFO_REG;

        for (; page_rva < segment_end; page_rva += OE_PAGE_SIZE)
        {
            OE_CHECK(oe_sgx_load_enclave_data(
                context,
                enclave->base_address,
                enclave->start_address + *vaddr + page_rva,
                (uint64_t)image->image_base + page_rva,
                flags,
                true));
        }
    }

    *vaddr = *vaddr + image->image_size;
    result = OE_OK;

done:
    return result;
}

/* Add an image to the enclave */
static oe_result_t _add_pages(
    const oe_enclave_image_t* image,
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr && (*vaddr == 0));

    size_t image_size = image->elf.image_size;
    if (image->submodule)
        OE_CHECK(oe_safe_add_sizet(
            image_size, image->submodule->image_size, &image_size));
    assert((image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert(enclave->size > image_size);

    /* Add the program segments first */
    OE_CHECK(_add_segment_pages(context, enclave, &image->elf, vaddr));
    if (image->submodule)
        OE_CHECK(_add_segment_pages(context, enclave, image->submodule, vaddr));

    /* The base image points to the merged (base + module), zero-padded
     * relocation data after the patching step. */
    OE_CHECK(_add_relocation_pages(context, enclave, &image->elf, vaddr));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_dynamic_symbol_rva(
    oe_enclave_elf_image_t* image,
    const char* name,
    uint64_t* rva)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};

    if (!image || !name || !rva)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (elf64_find_dynamic_symbol_by_name(&image->elf, name, &sym) != 0)
        goto done;

    *rva = sym.st_value;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _set_uint64_t_dynamic_symbol_value(
    oe_enclave_elf_image_t* image,
    const char* name,
    uint64_t value)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t sym = {0};
    uint64_t* symbol_address = NULL;

    if (elf64_find_dynamic_symbol_by_name(&image->elf, name, &sym) != 0)
        goto done;

    symbol_address = (uint64_t*)(image->image_base + sym.st_value);
    *symbol_address = value;

    result = OE_OK;
done:
    return result;
}

static oe_result_t _link_elf_image(
    oe_enclave_elf_image_t* image,
    oe_enclave_elf_image_t* dependency)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(image);
    assert(dependency);

    elf64_rela_t* relocs = NULL;
    uint64_t nrelocs = 0;
    const elf64_sym_t* symtab = NULL;
    size_t symtab_size = 0;

    if (elf64_get_dynamic_symbol_table(&image->elf, &symtab, &symtab_size) != 0)
        goto done;

    /* Iterate through relocation records in the target image */
    relocs = (elf64_rela_t*)image->reloc_data;
    nrelocs = image->reloc_size / sizeof(relocs[0]);

    for (size_t i = 0; i < nrelocs; i++)
    {
        elf64_rela_t* p = &relocs[i];

        /* Fix up the r_offset based on the image_rva */
        OE_CHECK(oe_safe_add_u64(p->r_offset, image->image_rva, &p->r_offset));

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Patch symbolic relocation records to avoid having symbol lookup
         * in the enclave */
        if (reloc_type == R_X86_64_GLOB_DAT ||
            reloc_type == R_X86_64_JUMP_SLOT || reloc_type == R_X86_64_64)
        {
            uint64_t symbol_index = ELF64_R_SYM(p->r_info);
            const elf64_sym_t* symbol = &symtab[symbol_index];
            const char* name =
                elf64_get_string_from_dynstr(&image->elf, symbol->st_name);
            if (name == NULL)
                OE_RAISE(OE_NOT_FOUND);

            int64_t addend = (reloc_type == R_X86_64_64) ? p->r_addend : 0;

            /* To simplify the in-enclave relocation handling, we convert
             * all the symbolic relocation types to X86_64_RELATIVE. */
            p->r_info = (symbol_index << 32) | R_X86_64_RELATIVE;

            /* Find the definition of the symbol in the image itself */
            elf64_sym_t symbol_definition = {0};
            if (elf64_find_dynamic_symbol_by_name(
                    &image->elf, name, &symbol_definition) == 0 &&
                symbol_definition.st_shndx != SHN_UNDEF)
            {
                OE_CHECK(oe_safe_add_s64(
                    (int64_t)image->image_rva,
                    (int64_t)symbol_definition.st_value,
                    &p->r_addend));
                OE_CHECK(oe_safe_add_s64(p->r_addend, addend, &p->r_addend));
            }
            /* Find the definition of the symbol in the dependent image */
            else if (
                elf64_find_dynamic_symbol_by_name(
                    &dependency->elf, name, &symbol_definition) == 0 &&
                symbol_definition.st_shndx != SHN_UNDEF)
            {
                OE_CHECK(oe_safe_add_s64(
                    (int64_t)dependency->image_rva,
                    (int64_t)symbol_definition.st_value,
                    &p->r_addend));
                OE_CHECK(oe_safe_add_s64(p->r_addend, addend, &p->r_addend));
            }
            else
            {
                if ((symbol->st_info >> 4) != STB_WEAK)
                    OE_RAISE_MSG(
                        OE_UNSUPPORTED_ENCLAVE_IMAGE,
                        "symbol %s not found\n",
                        name);
                else
                    OE_TRACE_WARNING("Weak symbol %s is not resolved\n");
            }
        }
        /* Patch non-symbolic relocation records */
        else if (reloc_type == R_X86_64_RELATIVE)
        {
            OE_CHECK(oe_safe_add_s64(
                p->r_addend, (int64_t)image->image_rva, &p->r_addend));
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _append_data_to_buffer(
    void* buffer,
    size_t buffer_size,
    size_t offset,
    void* data,
    size_t data_size)
{
    oe_result_t result = OE_FAILURE;
    uint64_t destination;
    size_t destination_size;

    if (!buffer || !data)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_safe_add_u64((uint64_t)buffer, offset, &destination));
    OE_CHECK(oe_safe_sub_sizet(buffer_size, offset, &destination_size));
    OE_CHECK(
        oe_memcpy_s((void*)destination, destination_size, data, data_size));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _merge_and_pad_relocations(
    oe_enclave_elf_image_t* image,
    oe_enclave_elf_image_t* module_image)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(image);

    void* reloc_data = NULL;
    size_t reloc_size = 0;

    reloc_size = image->reloc_size;
    if (module_image)
        OE_CHECK(
            oe_safe_add_u64(reloc_size, module_image->reloc_size, &reloc_size));

    reloc_size = oe_round_up_to_page_size(reloc_size);
    reloc_data = oe_memalign(OE_PAGE_SIZE, reloc_size);
    if (!reloc_data)
        OE_RAISE(OE_OUT_OF_MEMORY);
    memset(reloc_data, 0, reloc_size);

    if (image->reloc_data && image->reloc_size)
        OE_CHECK(oe_memcpy_s(
            reloc_data, reloc_size, image->reloc_data, image->reloc_size));

    if (module_image && module_image->reloc_data && module_image->reloc_size)
        OE_CHECK(_append_data_to_buffer(
            reloc_data,
            reloc_size,
            image->reloc_size,
            module_image->reloc_data,
            module_image->reloc_size));

    /* Free the original relocation data and point to the padded one */
    if (image->reloc_data)
        oe_memalign_free(image->reloc_data);
    image->reloc_data = reloc_data;
    image->reloc_size = reloc_size;

    result = OE_OK;

done:
    if (result != OE_OK)
        oe_memalign_free(reloc_data);

    return result;
}

static oe_result_t _patch_elf_image(
    oe_enclave_elf_image_t* image,
    oe_enclave_elf_image_t* module_image,
    size_t enclave_size,
    size_t tls_page_count,
    size_t extra_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_enclave_properties_t* oeprops;
    oe_enclave_module_info_t* module_info;
    uint64_t enclave_rva = 0;

    oeprops =
        (oe_sgx_enclave_properties_t*)(image->image_base + image->oeinfo_rva);

    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((image->reloc_size & (OE_PAGE_SIZE - 1)) == 0);
    if (module_image)
        assert((module_image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_size & (OE_PAGE_SIZE - 1)) == 0);

    oeprops->image_info.enclave_size = enclave_size;
    oeprops->image_info.oeinfo_rva = image->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Set _enclave_rva to its own rva offset */
    OE_CHECK(_get_dynamic_symbol_rva(image, "_enclave_rva", &enclave_rva));
    OE_CHECK(
        _set_uint64_t_dynamic_symbol_value(image, "_enclave_rva", enclave_rva));

    /* reloc right after image */
    oeprops->image_info.reloc_rva = image->image_size;
    if (module_image)
        OE_CHECK(oe_safe_add_u64(
            oeprops->image_info.reloc_rva,
            module_image->image_size,
            &oeprops->image_info.reloc_rva));
    /* Note that the image->reloc_size now holds the merged (base + module),
     * zero-padded relocation data. */
    oeprops->image_info.reloc_size = image->reloc_size;
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_rva", oeprops->image_info.reloc_rva));
    OE_CHECK(_set_uint64_t_dynamic_symbol_value(
        image, "_reloc_size", oeprops->image_info.reloc_size));

    /* heap is right after the padded relocs */
    OE_CHECK(oe_safe_add_u64(
        oeprops->image_info.reloc_rva,
        image->reloc_size,
        &oeprops->image_info.heap_rva));

    /* move heap past regions */
    oeprops->image_info.heap_rva += extra_size;

    if (image->tdata_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_rva", image->tdata_rva);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_size", image->tdata_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tdata_align", image->tdata_align);
    }
    if (image->tbss_size)
    {
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_size", image->tbss_size);
        _set_uint64_t_dynamic_symbol_value(
            image, "_tbss_align", image->tbss_align);
    }

    _set_uint64_t_dynamic_symbol_value(
        image,
        "_td_from_tcs_offset",
        (tls_page_count + OE_SGX_TCS_CONTROL_PAGES) * OE_PAGE_SIZE);

    if (module_image)
    {
        /* Update the _module_info global struct that is required by the enclave
         * to perform the init/fini functions of the module. Note that the
         * struct, defined as a global variable in the enclave image, is
         * initialized to zero by default */
        size_t module_info_rva = 0;
        OE_CHECK(
            _get_dynamic_symbol_rva(image, "_module_info", &module_info_rva));
        module_info =
            (oe_enclave_module_info_t*)(image->image_base + module_info_rva);
        if (!module_info)
            OE_RAISE_MSG(
                OE_INVALID_IMAGE,
                "Failed to locate _module_info in the image",
                NULL);
        module_info->base_rva = module_image->image_rva;

        elf64_shdr_t init_section = {0};
        if (elf64_find_section_header(
                &module_image->elf, ".init_array", &init_section) == 0)
        {
            OE_CHECK(oe_safe_add_u64(
                module_info->base_rva,
                init_section.sh_addr,
                &module_info->init_array_rva));
            module_info->init_array_size = init_section.sh_size;
        }

        elf64_shdr_t fini_section = {0};
        if (elf64_find_section_header(
                &module_image->elf, ".fini_array", &fini_section) == 0)
        {
            OE_CHECK(oe_safe_add_u64(
                module_info->base_rva,
                fini_section.sh_addr,
                &module_info->fini_array_rva));
            module_info->fini_array_size = fini_section.sh_size;
        }
    }

    /* Clear the hash when taking the measure */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    result = OE_OK;
done:
    return result;
}

static oe_result_t _get_symbol_rva(
    oe_enclave_elf_image_t* image,
    const char* name,
    uint64_t* rva)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_sym_t symbol = {0};

    if (!image || !name || !rva)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (elf64_find_symbol_by_name(&image->elf, name, &symbol) != 0)
        goto done;

    *rva = symbol.st_value;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_dynamic_section_relocations(
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_FAILURE;
    elf64_dyn_t* dynamic = NULL;
    size_t dynamic_size = 0;
    uint64_t dynamic_rva = 0;
    size_t number_of_entries = 0;
    elf64_rela_t* relocation_records = NULL;
    size_t relocation_size = 0;

    if (!image)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (elf64_find_section(
            &image->elf, ".dynamic", (uint8_t**)&dynamic, &dynamic_size) != 0)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE,
            "Failed to locate the .dynamic section in the submodule",
            NULL);
    if (!dynamic || !dynamic_size)
        OE_RAISE(OE_INVALID_IMAGE);

    /* The _DYNAMIC symbol holds the RVA of the dynamic section after loading,
     * which is different from its offset within the ELF file. */
    OE_CHECK(_get_symbol_rva(image, "_DYNAMIC", &dynamic_rva));

    /* First loop: count the number of entries that we support now */
    for (uint64_t i = 0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_STRTAB || dynamic[i].d_tag == DT_SYMTAB ||
            dynamic[i].d_tag == DT_RELA || dynamic[i].d_tag == DT_GNU_HASH ||
            dynamic[i].d_tag == DT_VERSYM)
            number_of_entries++;
    }

    /* Number of entries should never be zero as some of them (e.g., DT_STRTAB
     * and DT_SYMTAB) are mandatory. */
    if (!number_of_entries)
        OE_RAISE(OE_INVALID_IMAGE);

    OE_CHECK(oe_safe_mul_sizet(
        number_of_entries, sizeof(elf64_rela_t), &relocation_size));
    relocation_records = (elf64_rela_t*)malloc(relocation_size);
    if (!relocation_records)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Second loop: create a relocation record for each of supported entries
     * Each record has the type of R_X86_64_RELATIVE and will be handled as part
     * of the in-enclave relocation. */
    for (uint64_t i = 0, j = 0; dynamic[i].d_tag != DT_NULL; i++)
    {
        if (dynamic[i].d_tag == DT_STRTAB || dynamic[i].d_tag == DT_SYMTAB ||
            dynamic[i].d_tag == DT_RELA || dynamic[i].d_tag == DT_GNU_HASH ||
            dynamic[i].d_tag == DT_VERSYM)
        {
            uint64_t offset;
            uint64_t append;
            relocation_records[j].r_info = R_X86_64_RELATIVE;
            OE_CHECK(oe_safe_sub_u64(
                (uint64_t)&dynamic[i].d_un, (uint64_t)dynamic, &offset));
            OE_CHECK(oe_safe_add_u64(offset, dynamic_rva, &offset));
            OE_CHECK(oe_safe_add_u64(offset, image->image_rva, &offset));
            relocation_records[j].r_offset = offset;
            OE_CHECK(oe_safe_add_u64(
                (uint64_t)dynamic[i].d_un.d_ptr, image->image_rva, &append));
            relocation_records[j].r_addend = (elf64_sxword_t)append;
            j++;
        }
    }

    void* new_relocation_data = NULL;
    size_t new_relocation_size;
    OE_CHECK(oe_safe_add_sizet(
        image->reloc_size, relocation_size, &new_relocation_size));
    /* Cannot use realloc here as the image->reloc_data is allocated via
     * oe_memalign */
    new_relocation_data = oe_memalign(OE_PAGE_SIZE, new_relocation_size);
    if (!new_relocation_data)
        OE_RAISE(OE_OUT_OF_MEMORY);
    OE_CHECK(oe_memcpy_s(
        new_relocation_data,
        new_relocation_size,
        image->reloc_data,
        image->reloc_size));
    oe_memalign_free(image->reloc_data);
    OE_CHECK(_append_data_to_buffer(
        new_relocation_data,
        new_relocation_size,
        image->reloc_size,
        (void*)relocation_records,
        relocation_size));
    image->reloc_data = new_relocation_data;
    image->reloc_size = new_relocation_size;

    result = OE_OK;

done:
    free(relocation_records);

    return result;
}

static oe_result_t _patch_relocations(oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    if (image->submodule)
    {
        OE_CHECK(_link_elf_image(&image->elf, image->submodule));
        OE_CHECK(_link_elf_image(image->submodule, &image->elf));
        /* Add relocation records for the dynamic section to conform
         * the behavior of ld.so */
        OE_CHECK(_add_dynamic_section_relocations(image->submodule));
    }
    /* Merge the relocation data from both base and module (if any) images and
     * apply zero-paddings (to the next page size) */
    OE_CHECK(_merge_and_pad_relocations(&image->elf, image->submodule));

    result = OE_OK;
done:
    return result;
}

static oe_result_t _patch(
    oe_enclave_image_t* image,
    size_t enclave_size,
    size_t extra_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t tls_page_count;

    OE_CHECK(image->get_tls_page_count(image, &tls_page_count));
    OE_CHECK(_patch_elf_image(
        &image->elf,
        image->submodule,
        enclave_size,
        tls_page_count,
        extra_size));

    result = OE_OK;
done:
    return result;
}

static oe_result_t _get_debug_modules(
    oe_enclave_image_t* image,
    oe_enclave_t* enclave,
    oe_debug_module_t** modules)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_debug_module_t* debug_module = NULL;

    *modules = NULL;
    if (image->submodule)
    {
        debug_module = (oe_debug_module_t*)calloc(sizeof(*debug_module), 1);
        if (!debug_module)
            OE_RAISE(OE_OUT_OF_MEMORY);

        debug_module->magic = OE_DEBUG_MODULE_MAGIC;
        debug_module->version = 1;
        debug_module->next = NULL;

        debug_module->path = strdup(image->submodule->path);
        if (!debug_module->path)
            OE_RAISE(OE_OUT_OF_MEMORY);
        debug_module->path_length = strlen(debug_module->path);

        debug_module->base_address =
            (void*)(enclave->start_address + image->submodule->image_rva);
        debug_module->size = image->submodule->image_size;

        debug_module->enclave = enclave->debug_enclave;
        *modules = debug_module;
        debug_module = NULL;
    }
    result = OE_OK;
done:
    if (debug_module)
        free(debug_module);

    return result;
}

static oe_result_t _sgx_load_enclave_properties(
    const oe_enclave_image_t* image,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Copy from the image at oeinfo_rva. */
    OE_CHECK(oe_memcpy_s(
        properties,
        sizeof(*properties),
        image->elf.image_base + image->elf.oeinfo_rva,
        sizeof(*properties)));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_update_enclave_properties(
    const oe_enclave_image_t* image,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Copy to both the image and ELF file*/
    OE_CHECK(oe_memcpy_s(
        (uint8_t*)image->elf.elf.data + image->elf.oeinfo_file_pos,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

    OE_CHECK(oe_memcpy_s(
        image->elf.image_base + image->elf.oeinfo_rva,
        sizeof(*properties),
        properties,
        sizeof(*properties)));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _find_dependent_image(
    const char* enclave_path,
    oe_enclave_image_t* image,
    char** module_path)
{
    oe_result_t result = OE_OK;
    elf64_dyn_t* section_data = NULL;
    size_t section_size = 0;
    uint64_t number_of_entries;
    elf64_addr_t strtab_offset = 0;
    elf64_xword_t needed_offset = 0;
    char* module_name = NULL;
    char* path_name = NULL;
    size_t path_size = 0;
    const char* n = NULL;
    const char* p = NULL;

    assert(enclave_path);
    assert(image);

    if (module_path)
        *module_path = NULL;

    if (elf64_find_section(
            &image->elf.elf,
            ".dynamic",
            (uint8_t**)&section_data,
            &section_size) != 0)
        goto done;

    if (!section_data || !section_size)
        OE_RAISE(OE_INVALID_IMAGE);

    number_of_entries = section_size / sizeof(elf64_dyn_t);
    for (uint64_t i = 0; i < number_of_entries; i++)
    {
        /* Explicitly prevent the use of DT_RPATH and DT_RUNPATH that affects
         * the enclave measurement */
        if (section_data[i].d_tag == DT_RPATH ||
            section_data[i].d_tag == DT_RUNPATH)
            OE_RAISE_MSG(
                OE_UNSUPPORTED_ENCLAVE_IMAGE,
                "RPATH or RUNPATH should not be used in the enclave binary",
                NULL);

        if (section_data[i].d_tag == DT_STRTAB)
            strtab_offset = section_data[i].d_un.d_ptr;
        else if (section_data[i].d_tag == DT_NEEDED)
        {
            if (needed_offset)
                OE_RAISE_MSG(
                    OE_UNSUPPORTED_ENCLAVE_IMAGE,
                    "Specifying more than one dependent .so module is "
                    "unsupported",
                    NULL);
            needed_offset = section_data[i].d_un.d_val;
        }
    }

    /* Early return if the enclave does not have a dependent module. */
    if (!needed_offset)
        goto done;

    /* Abort is strstab_offset is not set (both offsets are required to
     * locate the module name) */
    if (!strtab_offset)
        OE_RAISE(OE_INVALID_IMAGE);

    uint64_t module_name_addr;
    OE_CHECK(oe_safe_add_u64(
        (uint64_t)image->elf.image_base, strtab_offset, &module_name_addr));
    OE_CHECK(
        oe_safe_add_u64(module_name_addr, needed_offset, &module_name_addr));
    module_name = (char*)module_name_addr;
    if (!module_name)
        OE_RAISE(OE_INVALID_IMAGE);

    /* Extract the module name from the path */
    n = module_name + strlen(module_name);
    while ((n - 1) >= module_name && *(n - 1) != '/' && *(n - 1) != '\\')
        --n;

    /* Find out the folder from the enclave path */
    p = enclave_path + strlen(enclave_path);
    while (p != enclave_path && *p != '/' && *p != '\\')
        --p;

    /* Allocate string to hold the module path */
    path_size = (size_t)(p - enclave_path) + strlen(n) + 2;
    path_name = calloc(1, path_size);
    if (!path_name)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (p != enclave_path)
        snprintf(
            path_name,
            path_size,
            "%.*s/%s",
            (int)(p - enclave_path),
            enclave_path,
            n);
    else /* Handle the case if the module path does not include directories */
        snprintf(path_name, path_size, "%s", n);

    *module_path = path_name;

done:
    return result;
}

static oe_result_t _load_dependent_image(
    const char* enclave_path,
    oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    char* module_path = NULL;
    oe_enclave_elf_image_t* module_image = NULL;

    /*
     * Load the module only if the enclave binary links against
     * the module (specifed in the .dynamic section) and the module is placed
     * under the same directory as the enclave binary.
     */
    OE_CHECK(_find_dependent_image(enclave_path, image, &module_path));
    if (module_path)
    {
        if (access(module_path, F_OK) != 0)
            OE_RAISE_MSG(
                OE_NOT_FOUND,
                "Failed to locate the module. Please place the module under "
                "the same directory as the enclave binary.",
                NULL);

        module_image =
            (oe_enclave_elf_image_t*)calloc(1, sizeof(*module_image));
        if (!module_image)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(_load_elf_image(module_path, module_image));
        /* Update the RVA for the module */
        module_image->image_rva = image->elf.image_size;
        image->submodule = module_image;
        module_image = NULL;
    }

    result = OE_OK;
done:
    if (module_path)
        free(module_path);
    if (module_image)
        free(module_image);

    return result;
}

static oe_result_t _load_primary_image(
    const char* path,
    oe_enclave_elf_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK(_load_elf_image(path, image));
    /* The RVA of the primary image is always zero. */
    image->image_rva = 0;

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
    OE_CHECK(_load_primary_image(path, &image->elf));

    /* Load the dependent image into memory */
    OE_CHECK(_load_dependent_image(path, image));

    /* Patch relocations right after the image loading
     * and make the relocation data size page-aligned. */
    OE_CHECK(_patch_relocations(image));

    /* Verify that primary enclave image properties are found */
    if (!image->elf.entry_rva)
        OE_RAISE_MSG(
            OE_UNSUPPORTED_ENCLAVE_IMAGE,
            "Enclave image is missing entry point.",
            NULL);

    if (!image->elf.oeinfo_rva || !image->elf.oeinfo_file_pos)
        OE_RAISE_MSG(
            OE_UNSUPPORTED_ENCLAVE_IMAGE,
            "Enclave image is missing .oeinfo section.",
            NULL);

    image->type = OE_IMAGE_TYPE_ELF;
    image->calculate_size = _calculate_size;
    image->get_tls_page_count = _get_tls_page_count;
    image->add_pages = _add_pages;
    image->sgx_patch = _patch;
    image->sgx_get_debug_modules = _get_debug_modules;
    image->sgx_load_enclave_properties = _sgx_load_enclave_properties;
    image->sgx_update_enclave_properties = _sgx_update_enclave_properties;
    image->unload = _unload_image;

    result = OE_OK;

done:

    if (OE_OK != result)
        _unload_image(image);

    return result;
}
