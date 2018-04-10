// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1
#include "strings.h"

#if defined(__linux__)
#include <cpuid.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <assert.h>
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/cpuid.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/files.h>
#include <openenclave/bits/load.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/defs.h>
#include <openenclave/host.h>
#include <string.h>
#include "enclave.h"
#include "memalign.h"

static OE_H_OnceType _enclave_init_once;

static void _InitializeExceptionHandling(void)
{
    _OE_InitializeHostException();
}

/*
**==============================================================================
**
** The per process enclave host side initialization.
**
**==============================================================================
*/

static void _InitializeEnclaveHost()
{
    OE_H_Once(&_enclave_init_once, _InitializeExceptionHandling);
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

static uint64_t _MakeSecinfoFlags(uint32_t flags)
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

static void _ResolveFlags(
    const OE_Segment segments[],
    size_t nsegments,
    uint64_t addr,
    uint64_t* flags)
{
    *flags = 0;
    uint64_t last = addr + OE_PAGE_SIZE - 1; /* last address in page */

    /* See if any part of this page falls within a segment */
    for (size_t i = 0; i < nsegments; i++)
    {
        const OE_Segment* seg = &segments[i];

        if ((addr >= seg->vaddr && addr < seg->vaddr + seg->memsz) ||
            (last >= seg->vaddr && last < seg->vaddr + seg->memsz))
        {
            *flags = _MakeSecinfoFlags(seg->flags);
            return;
        }
    }
}

static OE_Result _AddSegmentPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    uint64_t enclaveSize,
    const OE_Segment segments[],
    size_t nsegments,
    const OE_Page* pages,
    size_t npages,
    uint64_t* vaddr)
{
    OE_Result result = OE_UNEXPECTED;
    size_t i;

    if (!dev || !enclaveAddr || !enclaveSize || !segments || !nsegments ||
        !pages || !npages || !vaddr)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Add each page to the enclave */
    for (i = 0; i < npages; i++)
    {
        const OE_Page* page = &pages[i];
        uint64_t addr = enclaveAddr + (i * OE_PAGE_SIZE);
        uint64_t src = (uint64_t)page;
        uint64_t flags;
        bool extend = true;

        /* Get the memory protection flags for this page address */
        _ResolveFlags(segments, nsegments, src - (uint64_t)pages, &flags);

        /* If page not with segments ranges, then skip! */
        if (flags == 0)
            continue;

        flags |= SGX_SECINFO_REG;

        /* Fail if ADDR is not between BASEADDR and BASEADDR+SIZE */
        if (addr < enclaveAddr ||
            addr > enclaveAddr + enclaveSize - OE_PAGE_SIZE)
        {
            OE_THROW(OE_FAILURE);
        }

        OE_TRY(dev->eadd(dev, enclaveAddr, addr, src, flags, extend));

        (*vaddr) = (addr - enclaveAddr) + OE_PAGE_SIZE;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _AddFilledPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    uint64_t* vaddr,
    size_t npages,
    uint32_t filler,
    bool extend)
{
    OE_Page page;
    OE_Result result = OE_UNEXPECTED;
    size_t i;

    /* Reject invalid parameters */
    if (!dev || !enclaveAddr || !vaddr)
        OE_THROW(OE_INVALID_PARAMETER);

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
        uint64_t addr = enclaveAddr + *vaddr;
        uint64_t src = (uint64_t)&page;
        uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;

        OE_TRY(dev->eadd(dev, enclaveAddr, addr, src, flags, extend));
        (*vaddr) += OE_PAGE_SIZE;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _AddStackPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    uint64_t* vaddr,
    size_t npages)
{
    const bool extend = true;
    return _AddFilledPages(dev, enclaveAddr, vaddr, npages, 0xcccccccc, extend);
}

static OE_Result _AddHeapPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    uint64_t* vaddr,
    size_t npages)
{
    /* Do not measure heap pages */
    const bool extend = false;
    return _AddFilledPages(dev, enclaveAddr, vaddr, npages, 0, extend);
}

static OE_Result _AddControlPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    uint64_t enclaveSize,
    uint64_t entry,
    uint64_t* vaddr,
    OE_Enclave* enclave)
{
    OE_Result result = OE_UNEXPECTED;

    if (!dev || !enclaveAddr || !enclaveSize || !entry || !vaddr || !enclave)
        OE_THROW(OE_INVALID_PARAMETER);

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
            OE_THROW(OE_FAILURE);

        enclave->bindings[enclave->num_bindings++].tcs = enclaveAddr + *vaddr;
    }

    /* Add the TCS page */
    {
        OE_Page page;
        SGX_TCS* tcs;

        /* Zero-fill the TCS page */
        memset(&page, 0, sizeof(page));

        /* Set TCS to pointer to page */
        tcs = (SGX_TCS*)&page;

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
            uint64_t addr = enclaveAddr + *vaddr;
            uint64_t src = (uint64_t)&page;
            uint64_t flags = SGX_SECINFO_TCS;
            bool extend = true;

            OE_TRY(dev->eadd(dev, enclaveAddr, addr, src, flags, extend));
        }

        /* Increment the page size */
        (*vaddr) += OE_PAGE_SIZE;
    }

    /* Add two blank pages */
    OE_TRY(_AddFilledPages(dev, enclaveAddr, vaddr, 2, 0, true));

    /* Skip over guard page */
    (*vaddr) += OE_PAGE_SIZE;

    /* Add one blank pages (for either FS segment or GS segment) */
    OE_TRY(_AddFilledPages(dev, enclaveAddr, vaddr, 1, 0, true));

    /* Add one page for thread-specific data (TSD) slots */
    OE_TRY(_AddFilledPages(dev, enclaveAddr, vaddr, 1, 0, true));

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _CalculateEnclaveSize(
    const OE_Segment* segments,
    size_t nsegments,
    size_t relocSize,
    size_t ecallSize,
    size_t nheappages,
    size_t nstackpages,
    size_t num_bindings,
    size_t* enclaveEnd, /* end may be less than size due to rounding */
    size_t* enclaveSize)
{
    OE_Result result = OE_UNEXPECTED;
    size_t segmentsSize;
    size_t heapSize;
    size_t stackSize;
    size_t controlSize;

    if (enclaveSize)
        *enclaveSize = 0;

    if (!segments || !nsegments || !nheappages || !nstackpages ||
        !num_bindings || !enclaveSize)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Compute size in bytes of segments */
    OE_TRY(__OE_CalculateSegmentsSize(segments, nsegments, &segmentsSize));

    /* Compute size in bytes of the heap */
    heapSize = nheappages * OE_PAGE_SIZE;

    /* Compute size of the stack (one per TCS; include guard pages) */
    stackSize = OE_PAGE_SIZE + (nstackpages * OE_PAGE_SIZE) + OE_PAGE_SIZE;

    /* Compute the control size in bytes (6 pages total) */
    controlSize = 6 * OE_PAGE_SIZE;

    /* Compute end of the enclave */
    *enclaveEnd = segmentsSize + relocSize + ecallSize + heapSize +
                  (num_bindings * (stackSize + controlSize));

    /* Calculate the total size of the enclave */
    *enclaveSize = OE_RoundU64ToPow2(*enclaveEnd);

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _AddRelocationPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    const void* relocData,
    const size_t relocSize,
    uint64_t* vaddr)
{
    OE_Result result = OE_UNEXPECTED;

    if (!dev || !vaddr)
        OE_THROW(OE_INVALID_PARAMETER);

    if (relocData && relocSize)
    {
        const OE_Page* pages = (const OE_Page*)relocData;
        size_t npages = relocSize / sizeof(OE_Page);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclaveAddr + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_TRY(dev->eadd(dev, enclaveAddr, addr, src, flags, extend));
            (*vaddr) += sizeof(OE_Page);
        }
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _AddECallPages(
    OE_SGXDevice* dev,
    uint64_t enclaveAddr,
    const void* ecallData,
    const size_t ecallSize,
    uint64_t* vaddr)
{
    OE_Result result = OE_UNEXPECTED;

    if (!dev || !ecallData || !ecallSize || !vaddr)
        OE_THROW(OE_INVALID_PARAMETER);

    {
        const OE_Page* pages = (const OE_Page*)ecallData;
        size_t npages = ecallSize / sizeof(OE_Page);

        for (size_t i = 0; i < npages; i++)
        {
            uint64_t addr = enclaveAddr + *vaddr;
            uint64_t src = (uint64_t)&pages[i];
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            bool extend = true;

            OE_TRY(dev->eadd(dev, enclaveAddr, addr, src, flags, extend));
            (*vaddr) += sizeof(OE_Page);
        }
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _AddPages(
    OE_SGXDevice* dev,
    Elf64* elf,
    uint64_t enclaveAddr,
    size_t enclaveEnd,
    size_t enclaveSize,
    const OE_Segment segments[],
    size_t nsegments,
    const void* relocData,
    size_t relocSize,
    void* ecallData,
    size_t ecallSize,
    uint64_t entry, /* entry point address */
    size_t nheappages,
    size_t nstackpages,
    size_t num_bindings,
    OE_Enclave* enclave)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t vaddr = 0;
    size_t i;
    OE_Page* segpages = NULL;
    size_t nsegpages;
    size_t baseRelocPage;
    size_t baseECallPage;
    size_t baseHeapPage;

    /* Reject invalid parameters */
    if (!dev || !enclaveAddr || !enclaveSize || !segments || !nsegments ||
        !num_bindings || !nstackpages || !nheappages || !enclave)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* ATTN: Eliminate this step to save memory! */
    OE_TRY(__OE_CombineSegments(segments, nsegments, &segpages, &nsegpages));

    /* The relocation pages follow the segments */
    baseRelocPage = nsegpages;

    /* The ecall pages follow the relocation pages */
    baseECallPage = baseRelocPage + (relocSize / OE_PAGE_SIZE);

    /* The heap follows the ecall pages */
    baseHeapPage = baseECallPage + (ecallSize / OE_PAGE_SIZE);

    /* Patch the "__oe_baseRelocPage" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_baseRelocPage", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = baseRelocPage;
    }

    /* Patch the "__oe_numRelocPages" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_numRelocPages", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) =
            relocSize / OE_PAGE_SIZE;
    }

    /* Patch the "__oe_baseECallPage" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_baseECallPage", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = baseECallPage;
    }

    /* Patch the "__oe_numECallPages" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_numECallPages", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) =
            ecallSize / OE_PAGE_SIZE;
    }

    /* Patch the "__oe_baseHeapPage" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_baseHeapPage", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = baseHeapPage;
    }

    /* Patch the "__oe_numHeapPages" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_numHeapPages", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = nheappages;
    }

    /* Patch the "__oe_numPages" */
    {
        Elf64_Sym sym;
        uint64_t npages = enclaveEnd / OE_PAGE_SIZE;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_numPages", &sym) != 0)
            OE_THROW(OE_FAILURE);

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = npages;
    }

    /* Patch the "__oe_virtualBaseAddr" */
    {
        Elf64_Sym sym;

        if (Elf64_FindDynamicSymbolByName(elf, "__oe_virtualBaseAddr", &sym) !=
            0)
        {
            OE_THROW(OE_FAILURE);
        }

        *(uint64_t*)((uint8_t*)segpages + sym.st_value) = sym.st_value;
    }

    /* Add the program segments first */
    OE_TRY(
        _AddSegmentPages(
            dev,
            enclaveAddr,
            enclaveSize,
            segments,
            nsegments,
            segpages,
            nsegpages,
            &vaddr));

    /* Add the relocation pages (contain relocation entries) */
    OE_TRY(_AddRelocationPages(dev, enclaveAddr, relocData, relocSize, &vaddr));

    /* Add the ECALL pages */
    OE_TRY(_AddECallPages(dev, enclaveAddr, ecallData, ecallSize, &vaddr));

    /* Create the heap */
    OE_TRY(_AddHeapPages(dev, enclaveAddr, &vaddr, nheappages));

    for (i = 0; i < num_bindings; i++)
    {
        /* Add guard page */
        vaddr += OE_PAGE_SIZE;

        /* Create the stack for this thread control structure */
        OE_TRY(_AddStackPages(dev, enclaveAddr, &vaddr, nstackpages));

        /* Add guard page */
        vaddr += OE_PAGE_SIZE;

        /* Add the "control" pages */
        OE_TRY(
            _AddControlPages(
                dev, enclaveAddr, enclaveSize, entry, &vaddr, enclave));
    }

    if (vaddr != enclaveEnd)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:

    if (segpages)
        OE_MemalignFree(segpages);

    return result;
}

typedef struct _VisitSymData
{
    const Elf64* elf;
    const Elf64_Shdr* shdr;
    mem_t* mem;
    OE_Result result;
} VisitSymData;

static int _VisitSym(const Elf64_Sym* sym, void* data_)
{
    int rc = -1;
    VisitSymData* data = (VisitSymData*)data_;
    const Elf64_Shdr* shdr = data->shdr;
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
    if (!(name = Elf64_GetStringFromDynstr(data->elf, sym->st_name)))
    {
        rc = 0;
        goto done;
    }

    /* Add to array of ECALLS */
    {
        ECallNameAddr tmp;

        if (!(tmp.name = OE_Strdup(name)))
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

static OE_Result _BuildECallArray(OE_Enclave* enclave, Elf64* elf)
{
    OE_Result result = OE_UNEXPECTED;
    Elf64_Shdr shdr;

    /* Reject invalid parameters */
    if (!enclave || !elf)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Find the ".ecalls" section */
    if (Elf64_FindSectionHeader(elf, ".ecall", &shdr) != 0)
        OE_THROW(OE_FAILURE);

    /* Find all functions that reside in the ".ecalls" section */
    {
        VisitSymData data;
        mem_t mem = MEM_DYNAMIC_INIT;

        data.elf = elf;
        data.shdr = &shdr;
        data.mem = &mem;

        if (Elf64_VisitSymbols(elf, _VisitSym, &data) != 0)
            OE_THROW(OE_FAILURE);

        enclave->ecalls = (ECallNameAddr*)mem_ptr(&mem);
        enclave->num_ecalls = mem_size(&mem) / sizeof(ECallNameAddr);
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _SaveTextAddress(OE_Enclave* enclave, Elf64* elf)
{
    OE_Result result = OE_UNEXPECTED;
    Elf64_Shdr shdr;

    /* Reject invalid parameters */
    if (!enclave || !elf)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Find the ".text" section header */
    if (Elf64_FindSectionHeader(elf, ".text", &shdr) != 0)
        OE_THROW(OE_FAILURE);

    /* Save the offset of the text section */
    enclave->text = enclave->addr + shdr.sh_addr;

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_INLINE void _DumpRelocations(const void* data, size_t size)
{
    const Elf64_Rela* p = (const Elf64_Rela*)data;
    size_t n = size / sizeof(Elf64_Rela);

    printf("=== Relocations:\n");

    for (size_t i = 0; i < n; i++, p++)
    {
        if (p->r_offset == 0)
            break;

        printf("offset=%llx addend=%llx\n", p->r_offset, p->r_addend);
    }
}

/*
**==============================================================================
**
** _BuildECallData()
**
**     Build the ECALL pages that will be included in the enclave image. These
**     pages contain the virtual addresses of all ECALL functions. During an
**     ECALL, the enclave uses the function number for that call as an index
**     into the array of virtual addresses to obtain the virtual address of
**     the ECALL function.
**
**==============================================================================
*/

static OE_Result _BuildECallData(
    OE_Enclave* enclave,
    void** ecallData,
    size_t* ecallSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_ECallPages* data;
    size_t size = 0;

    if (ecallData)
        *ecallData = NULL;

    if (ecallSize)
        *ecallSize = 0;

    if (!enclave || !ecallData || !ecallSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Calculate size needed for the ECALL pages */
    size = __OE_RoundUpToPageSize(
        sizeof(OE_ECallPages) + (enclave->num_ecalls * sizeof(uint64_t)));

    /* Allocate the pages */
    if (!(data = (OE_ECallPages*)calloc(1, size)))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Initialize the pages */
    {
        data->magic = OE_ECALL_PAGES_MAGIC;
        data->num_vaddrs = enclave->num_ecalls;

        for (size_t i = 0; i < enclave->num_ecalls; i++)
            data->vaddrs[i] = enclave->ecalls[i].vaddr;
    }

    /* Set the output parameters */
    *ecallData = data;
    *ecallSize = size;

    result = OE_OK;

OE_CATCH:

    return result;
}

/*
**==============================================================================
**
** _InitializeEnclave()
**
**     Invokes first OE_ECall into the enclave to trigger rebase and set up
**     enclave runtime global state, such as CPUID information from host.
**
**==============================================================================
*/

static OE_Result _InitializeEnclave(OE_Enclave* enclave)
{
    OE_Result result = OE_UNEXPECTED;
    OE_InitEnclaveArgs args;

    // Initialize enclave cache of CPUID info for emulation
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
#if defined(__linux__)
        int supported = __get_cpuid(
            i,
            &args.cpuidTable[i][OE_CPUID_RAX],
            &args.cpuidTable[i][OE_CPUID_RBX],
            &args.cpuidTable[i][OE_CPUID_RCX],
            &args.cpuidTable[i][OE_CPUID_RDX]);
        if (!supported)
            OE_THROW(OE_UNSUPPORTED);
#elif defined(_WIN32)
        __cpuid(args.cpuidTable[i], i);
#endif
    }

    OE_TRY(OE_ECall(enclave, OE_FUNC_INIT_ENCLAVE, (uint64_t)&args, NULL));

    result = OE_OK;

OE_CATCH:
    return result;
}

/* Find enclave property struct within an .oeinfo section */
static OE_Result _FindEnclavePropertiesHeader(
    uint8_t* sectionData,
    size_t sectionSize,
    OE_EnclaveType enclaveType,
    size_t structSize,
    OE_EnclavePropertiesHeader** header)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t* p = sectionData;
    uint8_t* end = p + sectionSize;

    *header = NULL;

    /* While there are more enclave property structures */
    while (p < end)
    {
        OE_EnclavePropertiesHeader* h = (OE_EnclavePropertiesHeader*)p;

        if (h->enclaveType == enclaveType)
        {
            /* Calculate bytes reamining in section */
            size_t remaining = end - p;

            /* Check struct size constraints */
            if (remaining < structSize || h->size != structSize)
            {
                result = OE_FAILURE;
                goto done;
            }

            *header = h;
            result = OE_OK;
            goto done;
        }

        p += h->size;
    }

    /* Structure was not found */
    result = OE_NOT_FOUND;

done:
    return result;
}

OE_Result OE_LoadEnclaveProperties_SGX(
    const Elf64* elf,
    const char* sectionName,
    OE_EnclaveProperties_SGX* properties)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t* sectionData;
    size_t sectionSize;

    if (properties)
        memset(properties, 0, sizeof(OE_EnclaveProperties_SGX));

    /* Check for null parameter */
    if (!elf || !sectionName || !properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Get pointer to and size of the given section */
    if (Elf64_FindSection(elf, sectionName, &sectionData, &sectionSize) != 0)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    /* Find SGX enclave property struct */
    {
        OE_EnclavePropertiesHeader* header;

        if ((result = _FindEnclavePropertiesHeader(
                 sectionData,
                 sectionSize,
                 OE_ENCLAVE_TYPE_SGX,
                 sizeof(OE_EnclaveProperties_SGX),
                 &header)) != OE_OK)
        {
            result = OE_NOT_FOUND;
            goto done;
        }

        memcpy(properties, header, sizeof(OE_EnclaveProperties_SGX));
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_UpdateEnclaveProperties_SGX(
    const Elf64* elf,
    const char* sectionName,
    const OE_EnclaveProperties_SGX* properties)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t* sectionData;
    size_t sectionSize;

    /* Check for null parameter */
    if (!elf || !sectionName || !properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Get pointer to and size of the given section */
    if (Elf64_FindSection(elf, sectionName, &sectionData, &sectionSize) != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Find SGX enclave property struct */
    {
        OE_EnclavePropertiesHeader* header;

        if ((result = _FindEnclavePropertiesHeader(
                 sectionData,
                 sectionSize,
                 OE_ENCLAVE_TYPE_SGX,
                 sizeof(OE_EnclaveProperties_SGX),
                 &header)) != OE_OK)
        {
            goto done;
        }

        memcpy(header, properties, sizeof(OE_EnclaveProperties_SGX));
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ValidateEnclaveProperties_SGX(
    const OE_EnclaveProperties_SGX* properties,
    const char** errorMessage)
{
    OE_Result result = OE_UNEXPECTED;

    if (errorMessage)
        *errorMessage = NULL;

    /* Check for null parameters */
    if (!properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!OE_ValidAttributes(properties->config.attributes))
    {
        if (errorMessage)
            *errorMessage = "config.attributes";
        result = OE_FAILURE;
        goto done;
    }

    if (!OE_ValidNumHeapPages(properties->header.sizeSettings.numHeapPages))
    {
        if (errorMessage)
            *errorMessage = "header.sizeSettings.numHeapPages";
        result = OE_FAILURE;
        goto done;
    }

    if (!OE_ValidNumStackPages(properties->header.sizeSettings.numStackPages))
    {
        if (errorMessage)
            *errorMessage = "sizeSettings.numStackPages";
        result = OE_FAILURE;
        goto done;
    }

    if (!OE_ValidNumTCS(properties->header.sizeSettings.numTCS))
    {
        if (errorMessage)
            *errorMessage = "sizeSettings.numTCS";
        result = OE_FAILURE;
        goto done;
    }

    if (!OE_ValidProductID(properties->config.productID))
    {
        if (errorMessage)
            *errorMessage = "config.productID";
        result = OE_FAILURE;
        goto done;
    }

    if (!OE_ValidSecurityVersion(properties->config.productID))
    {
        if (errorMessage)
            *errorMessage = "config.securityVersion";
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

OE_Result __OE_BuildEnclave(
    OE_SGXDevice* dev,
    const char* path,
    const OE_EnclaveProperties_SGX* properties,
    bool debug,
    bool simulate,
    OE_Enclave* enclave)
{
    OE_Result result = OE_UNEXPECTED;
    OE_Segment segments[OE_MAX_SEGMENTS];
    size_t numSegments = 0;
    uint64_t entryAddr = 0;
    uint64_t startAddr = 0; /* ATTN: not used */
    size_t enclaveEnd = 0;
    size_t enclaveSize = 0;
    uint64_t enclaveAddr = 0;
    size_t i;
    Elf64 elf;
    void* relocData = NULL;
    size_t relocSize;
    void* ecallData = NULL;
    size_t ecallSize;

    memset(&elf, 0, sizeof(Elf64));

    /* Clear and initialize enclave structure */
    {
        if (enclave)
            memset(enclave, 0, sizeof(OE_Enclave));

        enclave->debug = debug;
        enclave->simulate = simulate;
    }

    /* Initialize the lock */
    if (OE_H_MutexInit(&enclave->lock))
        OE_THROW(OE_FAILURE);

    /* Reject invalid parameters */
    if (!dev || !path || !enclave)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Load the elf object */
    if (Elf64_Load(path, &elf) != 0)
        OE_THROW(OE_FAILURE);

    // If the **properties** parameter is non-null, use those properties.
    // Else use the properties stored in the .oeinfo section.
    if (properties)
    {
        enclave->properties = *properties;
    }
    else
    {
        OE_TRY(
            OE_LoadEnclaveProperties_SGX(
                &elf, OE_INFO_SECTION_NAME, &enclave->properties));
    }

    /* Validate the enclave properties structure */
    OE_TRY(OE_ValidateEnclaveProperties_SGX(&enclave->properties, NULL));

    /* Consolidate enclave-debug-flag with create-debug-flag */
    if (enclave->properties.config.attributes & OE_SGX_FLAGS_DEBUG)
    {
        if (!debug)
        {
            /* Upgrade to non-debug mode */
            enclave->properties.config.attributes &= ~OE_SGX_FLAGS_DEBUG;
        }
    }
    else
    {
        if (debug)
        {
            /* Attempted to downgrade to debug mode */
            OE_THROW(OE_DEBUG_DOWNGRADE);
        }
    }

    /* Load the program segments into memory */
    OE_TRY(
        __OE_LoadSegments(
            path, segments, &numSegments, &entryAddr, &startAddr));

    /* Load the relocations into memory (zero-padded to next page size) */
    if (Elf64_LoadRelocations(&elf, &relocData, &relocSize) != 0)
        OE_THROW(OE_FAILURE);
#if 0
    _DumpRelocations(relocData, relocSize);
#endif

    /* Build an array of all the ECALL functions in the .ecalls section */
    OE_TRY(_BuildECallArray(enclave, &elf));

    /* Build ECALL pages for enclave (list of addresses) */
    OE_TRY(_BuildECallData(enclave, &ecallData, &ecallSize));

    /* Calculate the size of this enclave in memory */
    OE_TRY(
        _CalculateEnclaveSize(
            segments,
            numSegments,
            relocSize,
            ecallSize,
            enclave->properties.header.sizeSettings.numHeapPages,
            enclave->properties.header.sizeSettings.numStackPages,
            enclave->properties.header.sizeSettings.numTCS,
            &enclaveEnd,
            &enclaveSize));

    /* Ask the ISGX driver to perform the ECREATE operation */
    OE_TRY(dev->ecreate(dev, enclaveSize, &enclaveAddr));

    /* Save the enclave base address and size */
    enclave->addr = enclaveAddr;
    enclave->size = enclaveSize;

    /* Clear certain ELF header fields */
    for (i = 0; i < numSegments; i++)
    {
        const OE_Segment* seg = &segments[i];
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)seg->filedata;

        if (Elf64_TestHeader(ehdr) == 0)
        {
            ehdr->e_shoff = 0;
            ehdr->e_shnum = 0;
            ehdr->e_shstrndx = 0;
            break;
        }
    }

    /* Add pages to enclave page cache (EPC) */
    OE_TRY(
        _AddPages(
            dev,
            &elf,
            enclaveAddr,
            enclaveEnd,
            enclaveSize,
            segments,
            numSegments,
            relocData,
            relocSize,
            ecallData,
            ecallSize,
            entryAddr,
            enclave->properties.header.sizeSettings.numHeapPages,
            enclave->properties.header.sizeSettings.numStackPages,
            enclave->properties.header.sizeSettings.numTCS,
            enclave));

#if defined(_WIN32)
    {
        OE_STATIC_ASSERT(
            OE_FIELD_SIZE(ENCLAVE_INIT_INFO_SGX, SigStruct) ==
            sizeof(props.sigstruct));
    }
#endif

    /* Ask the ISGX driver to initialize the enclave (and finalize the hash) */
    OE_TRY(dev->einit(dev, enclaveAddr, &enclave->properties));

    /* Get the hash and store it in the ENCLAVE object */
    OE_TRY(dev->gethash(dev, &enclave->hash));

    /* Save the offset of the .text section */
    OE_TRY(_SaveTextAddress(enclave, &elf));

    /* Save path of this enclave */
    if (!(enclave->path = OE_Strdup(path)))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Set the magic number */
    enclave->magic = ENCLAVE_MAGIC;

    result = OE_OK;

OE_CATCH:

    for (i = 0; i < numSegments; i++)
        free(segments[i].filedata);

    if (relocData)
        free(relocData);

    if (ecallData)
        free(ecallData);

    Elf64_Unload(&elf);

    return result;
}

#if defined(__linux__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

/*
** These functions are needed to notify the debugger. They should not be
** optimized out even they don't do anything in here.
*/

void _OE_NotifyGdbEnclaveTermination(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength)
{
    OE_UNUSED(enclave);
    OE_UNUSED(enclavePath);
    OE_UNUSED(enclavePathLength);

    return;
}

void _OE_NotifyGdbEnclaveCreation(
    const OE_Enclave* enclave,
    const char* enclavePath,
    uint32_t enclavePathLength)
{
    OE_UNUSED(enclave);
    OE_UNUSED(enclavePath);
    OE_UNUSED(enclavePathLength);

    return;
}

#if defined(__linux__)
#pragma GCC pop_options
#endif

OE_Result OE_CreateEnclave(
    const char* enclavePath,
    uint32_t flags,
    OE_Enclave** enclaveOut)
{
    OE_Result result = OE_UNEXPECTED;
    OE_Enclave* enclave = NULL;
    OE_SGXDevice* dev = NULL;
    bool simulate = false;
    bool debug = false;

    _InitializeEnclaveHost();

    if (enclaveOut)
        *enclaveOut = NULL;

    /* Check parameters */
    if (!enclavePath || !enclaveOut)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set simulate flag */
    if (flags & OE_FLAG_SIMULATE)
        simulate = true;

    /* Set debug flag */
    if (flags & OE_FLAG_DEBUG)
        debug = true;

    /* Allocate and zero-fill the enclave structure */
    if (!(enclave = (OE_Enclave*)calloc(1, sizeof(OE_Enclave))))
        OE_THROW(OE_OUT_OF_MEMORY);

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
            OE_THROW(OE_FAILURE);
        }
    }

#endif

    /* Open the SGX driver */
    if (!(dev = __OE_OpenSGXDriver(simulate)))
        OE_THROW(OE_FAILURE);

    /* Build the enclave */
    OE_TRY(__OE_BuildEnclave(dev, enclavePath, NULL, debug, simulate, enclave));

    /* Invoke enclave initialization */
    OE_TRY(_InitializeEnclave(enclave));

    /* Push the new created enclave to the global list. */
    if (_OE_PushEnclaveInstance(enclave) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Notify GDB that a new enclave is created */
    _OE_NotifyGdbEnclaveCreation(
        enclave, enclave->path, (uint32_t)strlen(enclave->path));

    *enclaveOut = enclave;
    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
    {
        if (enclave)
        {
            if (dev)
                dev->close(dev);

            free(enclave);
        }
    }

    return result;
}

OE_Result OE_TerminateEnclave(OE_Enclave* enclave)
{
    OE_Result result = OE_UNEXPECTED;
    size_t i;

    /* Check parameters */
    if (!enclave || enclave->magic != ENCLAVE_MAGIC)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Call the enclave destructor */
    OE_TRY(OE_ECall(enclave, OE_FUNC_DESTRUCTOR, 0, NULL));

    /* Notify GDB that this enclave is terminated */
    _OE_NotifyGdbEnclaveTermination(
        enclave, enclave->path, (uint32_t)strlen(enclave->path));

    /* Remove this enclave from the global list. */
    _OE_RemoveEnclaveInstance(enclave);

    /* Clear the magic number */
    enclave->magic = 0;

/* Unmap the enclave memory */
#if defined(__linux__)
    munmap((void*)enclave->addr, enclave->size);
#elif defined(_WIN32)
    VirtualFree((void*)enclave->addr, enclave->size, MEM_RELEASE);
#endif

    /* Release the enclave->ecalls[] array */
    {
        for (i = 0; i < enclave->num_ecalls; i++)
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

    /* Clear the contents of the enclave structure */
    memset(enclave, 0x00, sizeof(OE_Enclave));

    /* Free the enclave structure */
    free(enclave);

    result = OE_OK;

OE_CATCH:

    return result;
}
