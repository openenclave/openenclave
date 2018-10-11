// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "strings.h"

#if defined(__linux__)
#include <errno.h>
#include <sys/mman.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <assert.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/debug.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <string.h>
#include "cpuid.h"
#include "enclave.h"
#include "memalign.h"
#include "sgxload.h"

static oe_once_type _enclave_init_once;

static void _initialize_exception_handling(void)
{
    _oe_initialize_host_exception();
}

/*
**==============================================================================
**
** The per process enclave host side initialization.
**
**==============================================================================
*/

static void _initialize_enclave_host()
{
    oe_once(&_enclave_init_once, _initialize_exception_handling);
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

static void _resolve_flags(
    const oe_segment_t segments[],
    size_t nsegments,
    uint64_t addr,
    uint64_t* flags)
{
    *flags = 0;
    uint64_t last = addr + OE_PAGE_SIZE - 1; /* last address in page */

    /* See if any part of this page falls within a segment */
    for (size_t i = 0; i < nsegments; i++)
    {
        const oe_segment_t* seg = &segments[i];

        if ((addr >= seg->vaddr && addr < seg->vaddr + seg->memsz) ||
            (last >= seg->vaddr && last < seg->vaddr + seg->memsz))
        {
            *flags = _make_secinfo_flags(seg->flags);
            return;
        }
    }
}

static oe_result_t _add_segment_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t enclave_size,
    const oe_segment_t segments[],
    size_t nsegments,
    const oe_page_t* pages,
    size_t npages,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    if (!context || !enclave_addr || !enclave_size || !segments || !nsegments ||
        !pages || !npages || !vaddr)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Add each page to the enclave */
    for (i = 0; i < npages; i++)
    {
        const oe_page_t* page = &pages[i];
        uint64_t addr = enclave_addr + (i * OE_PAGE_SIZE);
        uint64_t src = (uint64_t)page;
        uint64_t flags;
        bool extend = true;

        /* Get the memory protection flags for this page address */
        _resolve_flags(segments, nsegments, src - (uint64_t)pages, &flags);

        /* If page not with segments ranges, then skip! */
        if (flags == 0)
            continue;

        flags |= SGX_SECINFO_REG;

        /* Fail if ADDR is not between BASEADDR and BASEADDR+SIZE */
        if (addr < enclave_addr ||
            addr > enclave_addr + enclave_size - OE_PAGE_SIZE)
        {
            OE_RAISE(OE_FAILURE);
        }

        OE_CHECK(
            oe_sgx_load_enclave_data(
                context, enclave_addr, addr, src, flags, extend));

        (*vaddr) = (addr - enclave_addr) + OE_PAGE_SIZE;
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_filled_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages,
    uint32_t filler,
    bool extend)
{
    oe_page_t page;
    oe_result_t result = OE_UNEXPECTED;
    size_t i;

    /* Reject invalid parameters */
    if (!context || !enclave_addr || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Fill or clear the page */
    if (filler)
    {
        size_t n = OE_PAGE_SIZE / sizeof(uint32_t);
        uint32_t* p = (uint32_t*)&page;

        while (n--)
            *p++ = filler;
    }
    else
        memset(&page, 0, sizeof(page));

    /* Add the pages */
    for (i = 0; i < npages; i++)
    {
        uint64_t addr = enclave_addr + *vaddr;
        uint64_t src = (uint64_t)&page;
        uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;

        OE_CHECK(
            oe_sgx_load_enclave_data(
                context, enclave_addr, addr, src, flags, extend));
        (*vaddr) += OE_PAGE_SIZE;
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_stack_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages)
{
    const bool extend = true;
    return _add_filled_pages(
        context, enclave_addr, vaddr, npages, 0xcccccccc, extend);
}

static oe_result_t _add_heap_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages)
{
    /* Do not measure heap pages */
    const bool extend = false;
    return _add_filled_pages(context, enclave_addr, vaddr, npages, 0, extend);
}

static oe_result_t _add_control_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t enclave_size,
    uint64_t entry,
    uint64_t* vaddr,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !enclave_addr || !enclave_size || !entry || !vaddr ||
        !enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create four "control" pages:
     *     page1 - page containing thread control structure (TCS)
     *     page2 - state-save-area (SSA) slot (zero-filled)
     *     page3 - state-save-area (SSA) slot (zero-filled)
     *     page4 - guard page
     *     page5 - segment space for fs or gs register (holds thread data).
     *     page6 - extra segment space for thread-specific data.
     */

    /* Save the address of new TCS page into enclave object */
    {
        if (enclave->num_bindings == OE_SGX_MAX_TCS)
            OE_RAISE(OE_FAILURE);

        enclave->bindings[enclave->num_bindings++].tcs = enclave_addr + *vaddr;
    }

    /* Add the TCS page */
    {
        oe_page_t page;
        sgx_tcs_t* tcs;

        /* Zero-fill the TCS page */
        memset(&page, 0, sizeof(page));

        /* Set TCS to pointer to page */
        tcs = (sgx_tcs_t*)&page;

        /* No flags for now */
        tcs->flags = 0;

        /* SSA resides on page immediately following the TCS page */
        tcs->ossa = *vaddr + OE_PAGE_SIZE;

        /* Used at runtime (set to zero for now) */
        tcs->cssa = 0;

        /* Reserve two slots (both which follow the TCS page) */
        tcs->nssa = 2;

        /* The entry point for the program (from ELF) */
        tcs->oentry = entry;

        /* FS segment: points to page following SSA slots (page[3]) */
        tcs->fsbase = *vaddr + (4 * OE_PAGE_SIZE);

        /* GS segment: points to page following SSA slots (page[3]) */
        tcs->gsbase = *vaddr + (4 * OE_PAGE_SIZE);

        /* Set to maximum value */
        tcs->fslimit = 0xFFFFFFFF;

        /* Set to maximum value */
        tcs->gslimit = 0xFFFFFFFF;

        /* Ask ISGX driver perform EADD on this page */
        {
            uint64_t addr = enclave_addr + *vaddr;
            uint64_t src = (uint64_t)&page;
            uint64_t flags = SGX_SECINFO_TCS;
            bool extend = true;

            OE_CHECK(
                oe_sgx_load_enclave_data(
                    context, enclave_addr, addr, src, flags, extend));
        }

        /* Increment the page size */
        (*vaddr) += OE_PAGE_SIZE;
    }

    /* Add two blank pages */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 2, 0, true));

    /* Skip over guard page */
    (*vaddr) += OE_PAGE_SIZE;

    /* Add one blank pages (for either FS segment or GS segment) */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 1, 0, true));

    /* Add one page for thread-specific data (TSD) slots */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 1, 0, true));

    result = OE_OK;

done:
    return result;
}

static oe_result_t _calculate_enclave_size(
    const oe_segment_t* segments,
    size_t nsegments,
    size_t reloc_size,
    size_t ecall_size,
    size_t nheappages,
    size_t nstackpages,
    size_t num_bindings,
    size_t* enclave_end, /* end may be less than size due to rounding */
    size_t* enclave_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t segments_size;
    size_t heap_size;
    size_t stack_size;
    size_t control_size;

    if (enclave_size)
        *enclave_size = 0;

    if (!segments || !nsegments || !nheappages || !nstackpages ||
        !num_bindings || !enclave_size)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Compute size in bytes of segments */
    OE_CHECK(__oe_calculate_segments_size(segments, nsegments, &segments_size));

    /* Compute size in bytes of the heap */
    heap_size = nheappages * OE_PAGE_SIZE;

    /* Compute size of the stack (one per TCS; include guard pages) */
    stack_size = OE_PAGE_SIZE + (nstackpages * OE_PAGE_SIZE) + OE_PAGE_SIZE;

    /* Compute the control size in bytes (6 pages total) */
    control_size = 6 * OE_PAGE_SIZE;

    /* Compute end of the enclave */
    *enclave_end = segments_size + reloc_size + ecall_size + heap_size +
                   (num_bindings * (stack_size + control_size));

    /* Calculate the total size of the enclave */
    *enclave_size = oe_round_u64_to_pow2(*enclave_end);

    result = OE_OK;

done:
    return result;
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

            OE_CHECK(
                oe_sgx_load_enclave_data(
                    context, enclave_addr, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_ecall_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    const void* ecall_data,
    const size_t ecall_size,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !ecall_data || !ecall_size || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        const oe_page_t* pages = (const oe_page_t*)ecall_data;
        size_t npages = ecall_size / sizeof(oe_page_t);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclave_addr + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_CHECK(
                oe_sgx_load_enclave_data(
                    context, enclave_addr, addr, src, flags, extend));
            (*vaddr) += sizeof(oe_page_t);
        }
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _patch_page(
    oe_page_t* segpages,
    size_t nsegpages,
    uint64_t offset,
    uint64_t value)
{
    uint8_t* pagebuf = (uint8_t*)segpages;

    /* Get the total size. */
    size_t size;
    oe_result_t ret = oe_safe_mul_sizet(nsegpages, sizeof(oe_page_t), &size);
    if (ret != OE_OK)
        return ret;

    /* Check for buffer overflow. */
    if (offset >= size)
        return OE_OUT_OF_BOUNDS;

    /* Ensure 8 byte alignment. */
    uint64_t page;
    ret = oe_safe_add_u64((uint64_t)pagebuf, offset, &page);
    if (ret != OE_OK)
        return ret;

    if (page % sizeof(uint64_t) != 0)
        return OE_BAD_ALIGNMENT;

    /* Patch the page. */
    *((uint64_t*)page) = value;

    return OE_OK;
}

static oe_result_t _add_pages(
    oe_sgx_load_context_t* context,
    elf64_t* elf,
    uint64_t enclave_addr,
    size_t enclave_end,
    size_t enclave_size,
    const oe_segment_t segments[],
    size_t nsegments,
    const void* reloc_data,
    size_t reloc_size,
    void* ecall_data,
    size_t ecall_size,
    uint64_t entry, /* entry point address */
    size_t nheappages,
    size_t nstackpages,
    size_t num_bindings,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t vaddr = 0;
    size_t i;
    oe_page_t* segpages = NULL;
    size_t nsegpages;
    size_t base_reloc_page;
    size_t base_ecall_page;
    size_t base_heap_page;

    /* Reject invalid parameters */
    if (!context || !enclave_addr || !enclave_size || !segments || !nsegments ||
        !num_bindings || !nstackpages || !nheappages || !enclave)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* ATTN: Eliminate this step to save memory! */
    OE_CHECK(__oe_combine_segments(segments, nsegments, &segpages, &nsegpages));

    /* The relocation pages follow the segments */
    base_reloc_page = nsegpages;

    /* The ecall pages follow the relocation pages */
    base_ecall_page = base_reloc_page + (reloc_size / OE_PAGE_SIZE);

    /* The heap follows the ecall pages */
    base_heap_page = base_ecall_page + (ecall_size / OE_PAGE_SIZE);

    /* Patch the "oe_base_reloc_page" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(
                elf, "oe_base_reloc_page", &sym) != 0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(
            _patch_page(segpages, nsegpages, sym.st_value, base_reloc_page));
    }

    /* Patch the "oe_num_reloc_pages" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(
                elf, "oe_num_reloc_pages", &sym) != 0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(
            _patch_page(
                segpages, nsegpages, sym.st_value, reloc_size / OE_PAGE_SIZE));
    }

    /* Patch the "oe_base_ecall_page" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(
                elf, "oe_base_ecall_page", &sym) != 0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(
            _patch_page(segpages, nsegpages, sym.st_value, base_ecall_page));
    }

    /* Patch the "oe_num_ecall_pages" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(
                elf, "oe_num_ecall_pages", &sym) != 0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(
            _patch_page(
                segpages, nsegpages, sym.st_value, ecall_size / OE_PAGE_SIZE));
    }

    /* Patch the "oe_base_heap_page" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(elf, "oe_base_heap_page", &sym) !=
            0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(
            _patch_page(segpages, nsegpages, sym.st_value, base_heap_page));
    }

    /* Patch the "oe_num_heap_pages" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(elf, "oe_num_heap_pages", &sym) !=
            0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(_patch_page(segpages, nsegpages, sym.st_value, nheappages));
    }

    /* Patch the "oe_num_pages" */
    {
        elf64_sym_t sym;
        uint64_t npages = enclave_end / OE_PAGE_SIZE;

        if (elf64_find_dynamic_symbol_by_name(elf, "oe_num_pages", &sym) != 0)
            OE_RAISE(OE_FAILURE);

        OE_CHECK(_patch_page(segpages, nsegpages, sym.st_value, npages));
    }

    /* Patch the "oe_virtual_base_addr" */
    {
        elf64_sym_t sym;

        if (elf64_find_dynamic_symbol_by_name(
                elf, "oe_virtual_base_addr", &sym) != 0)
        {
            OE_RAISE(OE_FAILURE);
        }

        OE_CHECK(_patch_page(segpages, nsegpages, sym.st_value, sym.st_value));
    }

    /* Add the program segments first */
    OE_CHECK(
        _add_segment_pages(
            context,
            enclave_addr,
            enclave_size,
            segments,
            nsegments,
            segpages,
            nsegpages,
            &vaddr));

    /* Add the relocation pages (contain relocation entries) */
    OE_CHECK(
        _add_relocation_pages(
            context, enclave_addr, reloc_data, reloc_size, &vaddr));

    /* Add the ECALL pages */
    OE_CHECK(
        _add_ecall_pages(
            context, enclave_addr, ecall_data, ecall_size, &vaddr));

    /* Create the heap */
    OE_CHECK(_add_heap_pages(context, enclave_addr, &vaddr, nheappages));

    for (i = 0; i < num_bindings; i++)
    {
        /* Add guard page */
        vaddr += OE_PAGE_SIZE;

        /* Create the stack for this thread control structure */
        OE_CHECK(_add_stack_pages(context, enclave_addr, &vaddr, nstackpages));

        /* Add guard page */
        vaddr += OE_PAGE_SIZE;

        /* Add the "control" pages */
        OE_CHECK(
            _add_control_pages(
                context, enclave_addr, enclave_size, entry, &vaddr, enclave));
    }

    if (vaddr != enclave_end)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (segpages)
        oe_memalign_free(segpages);

    return result;
}

typedef struct _visit_sym_data
{
    const elf64_t* elf;
    const elf64_shdr_t* shdr;
    mem_t* mem;
    oe_result_t result;
} VisitSymData;

static int _visit_sym(const elf64_sym_t* sym, void* data_)
{
    int rc = -1;
    VisitSymData* data = (VisitSymData*)data_;
    const elf64_shdr_t* shdr = data->shdr;
    const char* name;

    data->result = OE_UNEXPECTED;

    /* Skip symbol if not a function */
    if ((sym->st_info & 0x0F) != STT_FUNC)
    {
        rc = 0;
        goto done;
    }

    /* Skip symbol if not in the ".ecall" section */
    if (sym->st_value < shdr->sh_addr ||
        sym->st_value + sym->st_size > shdr->sh_addr + shdr->sh_size)
    {
        rc = 0;
        goto done;
    }

    /* Skip null names */
    if (!(name = elf64_get_string_from_dynstr(data->elf, sym->st_name)))
    {
        rc = 0;
        goto done;
    }

    /* Add to array of ECALLS */
    {
        ECallNameAddr tmp;

        if (!(tmp.name = oe_strdup(name)))
            goto done;

        tmp.code = StrCode(name, strlen(name));
        tmp.vaddr = sym->st_value;

        if (mem_cat(data->mem, &tmp, sizeof(tmp)) != 0)
            goto done;
    }

    rc = 0;

done:
    return rc;
}

static oe_result_t _build_ecall_array(oe_enclave_t* enclave, elf64_t* elf)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_shdr_t shdr;

    /* Reject invalid parameters */
    if (!enclave || !elf)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the ".ecalls" section */
    if (elf64_find_section_header(elf, ".ecall", &shdr) != 0)
        OE_RAISE(OE_FAILURE);

    /* Find all functions that reside in the ".ecalls" section */
    {
        VisitSymData data;
        mem_t mem = MEM_DYNAMIC_INIT;

        data.elf = elf;
        data.shdr = &shdr;
        data.mem = &mem;

        if (elf64_visit_symbols(elf, _visit_sym, &data) != 0)
            OE_RAISE(OE_FAILURE);

        enclave->ecalls = (ECallNameAddr*)mem_ptr(&mem);
        enclave->num_ecalls = mem_size(&mem) / sizeof(ECallNameAddr);
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _save_text_address(oe_enclave_t* enclave, elf64_t* elf)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_shdr_t shdr;

    /* Reject invalid parameters */
    if (!enclave || !elf)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Find the ".text" section header */
    if (elf64_find_section_header(elf, ".text", &shdr) != 0)
        OE_RAISE(OE_FAILURE);

    /* Save the offset of the text section */
    enclave->text = enclave->addr + shdr.sh_addr;

    result = OE_OK;

done:
    return result;
}

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
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
#endif

/*
**==============================================================================
**
** _build_ecall_data()
**
**     Build the ECALL pages that will be included in the enclave image. These
**     pages contain the virtual addresses of all ECALL functions. During an
**     ECALL, the enclave uses the function number for that call as an index
**     into the array of virtual addresses to obtain the virtual address of
**     the ECALL function.
**
**==============================================================================
*/

static oe_result_t _build_ecall_data(
    oe_enclave_t* enclave,
    void** ecall_data,
    size_t* ecall_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_ecall_pages_t* data;
    size_t size = 0;

    if (ecall_data)
        *ecall_data = NULL;

    if (ecall_size)
        *ecall_size = 0;

    if (!enclave || !ecall_data || !ecall_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Calculate size needed for the ECALL pages */
    size = __oe_round_up_to_page_size(
        sizeof(oe_ecall_pages_t) + (enclave->num_ecalls * sizeof(uint64_t)));

    /* Allocate the pages */
    if (!(data = (oe_ecall_pages_t*)calloc(1, size)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the pages */
    {
        data->magic = OE_ECALL_PAGES_MAGIC;
        data->num_vaddrs = enclave->num_ecalls;

        for (size_t i = 0; i < enclave->num_ecalls; i++)
            data->vaddrs[i] = enclave->ecalls[i].vaddr;
    }

    /* Set the output parameters */
    *ecall_data = data;
    *ecall_size = size;

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** _initialize_enclave()
**
**     Invokes first oe_ecall into the enclave to trigger rebase and set up
**     enclave runtime global state, such as CPUID information from host.
**
**==============================================================================
*/

static oe_result_t _initialize_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_init_enclave_args_t args;
    unsigned int subleaf = 0; // pass sub-leaf of 0 - needed for leaf 4

    // Initialize enclave cache of CPUID info for emulation
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        oe_get_cpuid(
            i,
            subleaf,
            &args.cpuid_table[i][OE_CPUID_RAX],
            &args.cpuid_table[i][OE_CPUID_RBX],
            &args.cpuid_table[i][OE_CPUID_RCX],
            &args.cpuid_table[i][OE_CPUID_RDX]);
    }

    // Pass the enclave handle to the enclave.
    args.enclave = enclave;

    OE_CHECK(oe_ecall(enclave, OE_ECALL_INIT_ENCLAVE, (uint64_t)&args, NULL));

    result = OE_OK;

done:
    return result;
}

/* Find enclave property struct within an .oeinfo section */
static oe_result_t _find_enclave_properties_header(
    uint8_t* section_data,
    size_t section_size,
    oe_enclave_type_t enclave_type,
    size_t struct_size,
    oe_enclave_properties_header_t** header)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* ptr = section_data;
    size_t bytes_remaining = section_size;

    *header = NULL;

    /* While there are more enclave property structures */
    while (bytes_remaining >= struct_size)
    {
        oe_enclave_properties_header_t* h =
            (oe_enclave_properties_header_t*)ptr;

        if (h->enclave_type == enclave_type)
        {
            if (h->size != struct_size)
            {
                result = OE_FAILURE;
                goto done;
            }

            /* Found it! */
            *header = h;
            break;
        }

        /* If size of structure extends beyond end of section */
        if (h->size > bytes_remaining)
            break;

        ptr += h->size;
        bytes_remaining -= h->size;
    }

    if (*header == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_load_properties(
    const elf64_t* elf,
    const char* section_name,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* section_data;
    size_t section_size;

    if (properties)
        memset(properties, 0, sizeof(*properties));

    /* Check for null parameter */
    if (!elf || !section_name || !properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Get pointer to and size of the given section */
    if (elf64_find_section(elf, section_name, &section_data, &section_size) !=
        0)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    /* Find SGX enclave property struct */
    {
        oe_enclave_properties_header_t* header;

        if ((result = _find_enclave_properties_header(
                 section_data,
                 section_size,
                 OE_ENCLAVE_TYPE_SGX,
                 sizeof(oe_sgx_enclave_properties_t),
                 &header)) != OE_OK)
        {
            result = OE_NOT_FOUND;
            goto done;
        }

        OE_CHECK(
            oe_memcpy_s(
                properties, sizeof(*properties), header, sizeof(*properties)));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_update_enclave_properties(
    const elf64_t* elf,
    const char* section_name,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* section_data;
    size_t section_size;

    /* Check for null parameter */
    if (!elf || !section_name || !properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Get pointer to and size of the given section */
    if (elf64_find_section(elf, section_name, &section_data, &section_size) !=
        0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Find SGX enclave property struct */
    {
        oe_enclave_properties_header_t* header;

        if ((result = _find_enclave_properties_header(
                 section_data,
                 section_size,
                 OE_ENCLAVE_TYPE_SGX,
                 sizeof(oe_sgx_enclave_properties_t),
                 &header)) != OE_OK)
        {
            goto done;
        }

        OE_CHECK(
            oe_memcpy_s(
                header, sizeof(*properties), properties, sizeof(*properties)));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_validate_enclave_properties(
    const oe_sgx_enclave_properties_t* properties,
    const char** field_name)
{
    oe_result_t result = OE_UNEXPECTED;

    if (field_name)
        *field_name = NULL;

    /* Check for null parameters */
    if (!properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!oe_sgx_is_valid_attributes(properties->config.attributes))
    {
        if (field_name)
            *field_name = "config.attributes";
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_heap_pages(
            properties->header.size_settings.num_heap_pages))
    {
        if (field_name)
            *field_name = "header.size_settings.num_heap_pages";
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_stack_pages(
            properties->header.size_settings.num_stack_pages))
    {
        if (field_name)
            *field_name = "header.size_settings.num_stack_pages";
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_tcs(properties->header.size_settings.num_tcs))
    {
        if (field_name)
            *field_name = "header.size_settings.num_tcs";
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_product_id(properties->config.product_id))
    {
        if (field_name)
            *field_name = "config.product_id";
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_security_version(properties->config.product_id))
    {
        if (field_name)
            *field_name = "config.security_version";
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_build_enclave(
    oe_sgx_load_context_t* context,
    const char* path,
    const oe_sgx_enclave_properties_t* properties,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_segment_t segments[OE_MAX_SEGMENTS];
    size_t num_segments = 0;
    uint64_t entry_addr = 0;
    uint64_t start_addr = 0; /* ATTN: not used */
    size_t enclave_end = 0;
    size_t enclave_size = 0;
    uint64_t enclave_addr = 0;
    size_t i;
    elf64_t elf;
    void* reloc_data = NULL;
    size_t reloc_size;
    void* ecall_data = NULL;
    size_t ecall_size;
    oe_sgx_enclave_properties_t props;

    memset(&elf, 0, sizeof(elf64_t));

    /* Clear and initialize enclave structure */
    {
        if (enclave)
            memset(enclave, 0, sizeof(oe_enclave_t));

        enclave->debug = oe_sgx_is_debug_load_context(context);
        enclave->simulate = oe_sgx_is_simulation_load_context(context);
    }

    /* Initialize the lock */
    if (oe_mutex_init(&enclave->lock))
        OE_RAISE(OE_FAILURE);

    /* Reject invalid parameters */
    if (!context || !path || !enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the elf object */
    if (elf64_load(path, &elf) != 0)
        OE_RAISE(OE_FAILURE);

    // If the **properties** parameter is non-null, use those properties.
    // Else use the properties stored in the .oeinfo section.
    if (properties)
    {
        props = *properties;
    }
    else
    {
        OE_CHECK(oe_sgx_load_properties(&elf, OE_INFO_SECTION_NAME, &props));
    }

    /* Validate the enclave properties structure */
    OE_CHECK(oe_sgx_validate_enclave_properties(&props, NULL));

    /* Consolidate enclave-debug-flag with create-debug-flag */
    if (props.config.attributes & OE_SGX_FLAGS_DEBUG)
    {
        if (!enclave->debug)
        {
            /* Upgrade to non-debug mode */
            props.config.attributes &= ~OE_SGX_FLAGS_DEBUG;
        }
    }
    else
    {
        if (enclave->debug)
        {
            /* Attempted to downgrade to debug mode */
            OE_RAISE(OE_DEBUG_DOWNGRADE);
        }
    }

    /* Load the program segments into memory */
    OE_CHECK(
        __oe_load_segments(
            path, segments, &num_segments, &entry_addr, &start_addr));

    /* Load the relocations into memory (zero-padded to next page size) */
    if (elf64_load_relocations(&elf, &reloc_data, &reloc_size) != OE_OK)
        OE_RAISE(OE_FAILURE);

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    _dump_relocations(reloc_data, reloc_size);
#endif

    /* Build an array of all the ECALL functions in the .ecalls section */
    OE_CHECK(_build_ecall_array(enclave, &elf));

    /* Build ECALL pages for enclave (list of addresses) */
    OE_CHECK(_build_ecall_data(enclave, &ecall_data, &ecall_size));

    /* Calculate the size of this enclave in memory */
    OE_CHECK(
        _calculate_enclave_size(
            segments,
            num_segments,
            reloc_size,
            ecall_size,
            props.header.size_settings.num_heap_pages,
            props.header.size_settings.num_stack_pages,
            props.header.size_settings.num_tcs,
            &enclave_end,
            &enclave_size));

    /* Perform the ECREATE operation */
    OE_CHECK(oe_sgx_create_enclave(context, enclave_size, &enclave_addr));

    /* Save the enclave base address and size */
    enclave->addr = enclave_addr;
    enclave->size = enclave_size;

    /* Clear certain ELF header fields */
    for (i = 0; i < num_segments; i++)
    {
        const oe_segment_t* seg = &segments[i];
        elf64_ehdr_t* ehdr = (elf64_ehdr_t*)seg->filedata;

        if (elf64_test_header(ehdr) == 0)
        {
            ehdr->e_shoff = 0;
            ehdr->e_shnum = 0;
            ehdr->e_shstrndx = 0;
            break;
        }
    }

    /* Add pages to enclave page cache (EPC) */
    OE_CHECK(
        _add_pages(
            context,
            &elf,
            enclave_addr,
            enclave_end,
            enclave_size,
            segments,
            num_segments,
            reloc_data,
            reloc_size,
            ecall_data,
            ecall_size,
            entry_addr,
            props.header.size_settings.num_heap_pages,
            props.header.size_settings.num_stack_pages,
            props.header.size_settings.num_tcs,
            enclave));

    /* Ask the platform to initialize the enclave and finalize the hash */
    OE_CHECK(
        oe_sgx_initialize_enclave(
            context, enclave_addr, &props, &enclave->hash));

    /* Save the offset of the .text section */
    OE_CHECK(_save_text_address(enclave, &elf));

    /* Save path of this enclave */
    if (!(enclave->path = oe_strdup(path)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Set the magic number only if we have actually created an enclave */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE)
        enclave->magic = ENCLAVE_MAGIC;

    result = OE_OK;

done:

    for (i = 0; i < num_segments; i++)
        free(segments[i].filedata);

    if (reloc_data)
        free(reloc_data);

    if (ecall_data)
        free(ecall_data);

    elf64_unload(&elf);

    return result;
}

/*
** These functions are needed to notify the debugger. They should not be
** optimized out even though they don't do anything in here.
*/

OE_NO_OPTIMIZE_BEGIN

OE_NEVER_INLINE void _oe_notify_gdb_enclave_termination(
    const oe_enclave_t* enclave,
    const char* enclave_path,
    uint32_t enclave_path_length)
{
    OE_UNUSED(enclave);
    OE_UNUSED(enclave_path);
    OE_UNUSED(enclave_path_length);

    return;
}

OE_NEVER_INLINE void _oe_notify_gdb_enclave_creation(
    const oe_enclave_t* enclave,
    const char* enclave_path,
    uint32_t enclave_path_length)
{
    OE_UNUSED(enclave);
    OE_UNUSED(enclave_path);
    OE_UNUSED(enclave_path_length);

    return;
}

OE_NO_OPTIMIZE_END

/*
** This method encapsulates all steps of the enclave creation process:
**     - Loads an enclave image file
**     - Lays out the enclave memory image and injects enclave metadata
**     - Asks the platform to create the enclave (ECREATE)
**     - Asks the platform to add the pages to the EPC (EADD/EEXTEND)
**     - Asks the platform to initialize the enclave (EINIT)
**
** When built against the legacy Intel(R) SGX driver and Intel(R) AESM service
** dependencies, this method also:
**     - Maps the enclave memory image onto the driver device (/dev/isgx) for
**        ECREATE.
**     - Obtains a launch token (EINITKEY) from the Intel(R) launch enclave (LE)
**        for EINIT.
*/
oe_result_t oe_create_enclave(
    const char* enclave_path,
    oe_enclave_type_t enclave_type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    oe_enclave_t** enclave_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave = NULL;
    oe_sgx_load_context_t context;

    _initialize_enclave_host();

    if (enclave_out)
        *enclave_out = NULL;

    /* Check parameters */
    if (!enclave_path || !enclave_out || enclave_type != OE_ENCLAVE_TYPE_SGX ||
        (flags & OE_ENCLAVE_FLAG_RESERVED) || config || config_size > 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate and zero-fill the enclave structure */
    if (!(enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t))))
        OE_RAISE(OE_OUT_OF_MEMORY);

#if defined(_WIN32)

    /* Create Windows events for each TCS binding. Enclaves use
     * this event when calling into the host to handle waits/wakes
     * as part of the enclave mutex and condition variable
     * implementation.
     */
    for (size_t i = 0; i < enclave->num_bindings; i++)
    {
        ThreadBinding* binding = &enclave->bindings[i];

        if (!(binding->event.handle = CreateEvent(
                  0,     /* No security attributes */
                  FALSE, /* Event is reset automatically */
                  FALSE, /* Event is not put in a signaled state
                            upon creation */
                  0)))   /* No name */
        {
            OE_RAISE(OE_FAILURE);
        }
    }

#endif

    /* Initialize the context parameter and any driver handles */
    OE_CHECK(
        oe_sgx_initialize_load_context(
            &context, OE_SGX_LOAD_TYPE_CREATE, flags));

    /* Build the enclave */
    OE_CHECK(oe_sgx_build_enclave(&context, enclave_path, NULL, enclave));

    /* Push the new created enclave to the global list. */
    if (_oe_push_enclave_instance(enclave) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Notify GDB that a new enclave is created */
    _oe_notify_gdb_enclave_creation(
        enclave, enclave->path, (uint32_t)strlen(enclave->path));

    /* Enclave initialization invokes global constructors which could make
     * ocalls. Therefore setup ocall table prior to initialization. */
    enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
    enclave->num_ocalls = ocall_table_size;

    /* Invoke enclave initialization. */
    OE_CHECK(_initialize_enclave(enclave));

    *enclave_out = enclave;
    result = OE_OK;

done:

    if (result != OE_OK && enclave)
    {
        for (size_t i = 0; i < enclave->num_ecalls; i++)
            free(enclave->ecalls[i].name);

        free(enclave->ecalls);
        free(enclave);
    }

    oe_sgx_cleanup_load_context(&context);

    return result;
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Check parameters */
    if (!enclave || enclave->magic != ENCLAVE_MAGIC)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Call the enclave destructor */
    OE_CHECK(oe_ecall(enclave, OE_ECALL_DESTRUCTOR, 0, NULL));

    /* Notify GDB that this enclave is terminated */
    _oe_notify_gdb_enclave_termination(
        enclave, enclave->path, (uint32_t)strlen(enclave->path));

    /* Once the enclave destructor has been invoked, the enclave memory
     * and data structures are freed on a best effort basis from here on */

    /* Remove this enclave from the global list. */
    _oe_remove_enclave_instance(enclave);

    /* Clear the magic number */
    enclave->magic = 0;

    oe_mutex_lock(&enclave->lock);
    {
        /* Unmap the enclave memory region.
         * Track failures reported by the platform, but do not exit early */
        result = oe_sgx_delete_enclave(enclave);

        /* Release the enclave->ecalls[] array */
        {
            for (size_t i = 0; i < enclave->num_ecalls; i++)
                free(enclave->ecalls[i].name);

            free(enclave->ecalls);
        }

#if defined(_WIN32)

        /* Release Windows events created during enclave creation */
        for (size_t i = 0; i < enclave->num_bindings; i++)
        {
            ThreadBinding* binding = &enclave->bindings[i];
            CloseHandle(binding->event.handle);
        }

#endif

        /* Free the path name of the enclave image file */
        free(enclave->path);
    }
    /* Release and destroy the mutex object */
    oe_mutex_unlock(&enclave->lock);
    oe_mutex_destroy(&enclave->lock);

    /* Clear the contents of the enclave structure */

    memset(enclave, 0, sizeof(oe_enclave_t));

    /* Free the enclave structure */
    free(enclave);

done:

    return result;
}
