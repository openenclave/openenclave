// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/host.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>
#include <string.h>
#include "../memalign.h"
#include "../strings.h"
#include "enclave.h"
#include "sgxload.h"

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include "../linux/windows.h"
#endif

/* Redefine IMAGE_FIRST_SECTION on Linux */
#if defined(__linux__)
#undef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader)                                       \
    ((PIMAGE_SECTION_HEADER)(                                               \
        (UINT8*)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + \
        ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

static oe_result_t _oe_get_nt_header(
    char* image_base,
    PIMAGE_NT_HEADERS* nt_header)
{
    oe_result_t result = OE_UNEXPECTED;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_hdr;

    *nt_header = NULL;
    dos_header = (PIMAGE_DOS_HEADER)image_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        OE_RAISE(OE_FAILURE);
    }

    nt_hdr = (PIMAGE_NT_HEADERS)(image_base + dos_header->e_lfanew);

    /* must a 64-bit image_base */
    if (((char*)nt_hdr < image_base) ||
        (nt_hdr->Signature != IMAGE_NT_SIGNATURE) ||
        (nt_hdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) ||
        (nt_hdr->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        OE_RAISE(OE_FAILURE);
    }

    *nt_header = nt_hdr;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _sgx_load_enclave_properties(
    const oe_enclave_image_t* image,
    const char* sectionName, // unused
    oe_sgx_enclave_properties_t* properties)
{
    OE_UNUSED(sectionName);
    assert(image);
    assert(image->oeinfo_rva);
    assert(properties);

    memcpy(
        properties, image->image_base + image->oeinfo_rva, sizeof(*properties));
    return OE_OK;
}

static oe_result_t _sgx_update_enclave_properties(
    const oe_enclave_image_t* image,
    const char* sectionName, // unused
    const oe_sgx_enclave_properties_t* properties)
{
    OE_UNUSED(sectionName);
    assert(image);
    assert(image->oeinfo_rva);
    assert(properties);

    memcpy(
        image->image_base + image->oeinfo_rva, properties, sizeof(*properties));
    return OE_OK;
}

static oe_result_t _unload(oe_enclave_image_t* image)
{
    if (image->u.pe.module)
    {
        FreeLibrary((HMODULE)image->u.pe.module);
    }
    memset(image, 0, sizeof(oe_enclave_image_t));
    return OE_OK;
}

static oe_result_t _calculate_size(
    const oe_enclave_image_t* image,
    size_t* image_size)
{
    assert(image && image_size);
    *image_size = image->image_size;

    return OE_OK;
}

static uint64_t _make_secinfo_flags(uint32_t Characteristics)
{
    uint32_t r = 0;

    if (Characteristics & IMAGE_SCN_MEM_READ)
    {
        r |= SGX_SECINFO_R;
    }

    if (Characteristics & IMAGE_SCN_MEM_WRITE)
    {
        r |= SGX_SECINFO_W;
    }

    if (Characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        r |= SGX_SECINFO_X;
    }

    return r;
}

static oe_result_t _add_section_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclaveAddr,
    const IMAGE_SECTION_HEADER* section_hdr,
    void* image)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t flags;
    size_t i;

    assert(context);
    assert(section_hdr);
    assert(image);

    flags = _make_secinfo_flags(section_hdr->Characteristics);

    if (flags == 0)
    {
        /* should we fail or just skip? follow the old logic for now*/
        result = OE_OK;
        goto done;
    }

    flags |= SGX_SECINFO_REG;

    for (i = 0; i < section_hdr->Misc.VirtualSize; i += OE_PAGE_SIZE)
    {
        uint64_t offset = section_hdr->VirtualAddress + i;
        OE_CHECK(oe_sgx_load_enclave_data(
            context,
            enclaveAddr,
            enclaveAddr + offset,
            (uint64_t)image + offset,
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
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)image->u.pe.nt_header;
    PIMAGE_SECTION_HEADER section_hdr;
    size_t i;

    assert(context);
    assert(enclave);
    assert(image);
    assert(vaddr && (*vaddr == 0));
    assert((image->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert(enclave->size > image->image_size);

    section_hdr = IMAGE_FIRST_SECTION(nt_header);

    /* Add image header as r/o pages */
    for (i = 0; i < section_hdr->VirtualAddress; i += OE_PAGE_SIZE)
    {
        OE_CHECK(oe_sgx_load_enclave_data(
            context,
            enclave->addr,
            enclave->addr + i,
            (uint64_t)image->image_base + i,
            SGX_SECINFO_R | SGX_SECINFO_REG,
            true));
    }

    /* Add all the sections. */
    for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_hdr++)
    {
        OE_CHECK(_add_section_pages(
            context, enclave->addr, section_hdr, image->image_base));
    }

    *vaddr = image->image_size;
    result = OE_OK;

done:
    return result;
}

static oe_result_t _build_ecall_array(
    oe_enclave_image_t* image,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    const IMAGE_DATA_DIRECTORY* exh;
    const IMAGE_EXPORT_DIRECTORY* exd;
    const IMAGE_NT_HEADERS* nt_header;
    uint32_t* name_table;
    uint32_t* func_table;
    const char* image_base;
    ECallNameAddr* ecall;
    uint32_t i;
    UINT32 AddressOfNames;
    UINT32 AddressOfFunctions;

    assert(enclave);
    assert(image);

    image_base = image->image_base;
    nt_header = (const IMAGE_NT_HEADERS*)image->u.pe.nt_header;
    exh =
        &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)exh->VirtualAddress + exh->Size > image->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    exd = (const IMAGE_EXPORT_DIRECTORY*)(image_base + exh->VirtualAddress);

    /* All exports must be named */
    if (exd->NumberOfFunctions != exd->NumberOfNames)
    {
        OE_RAISE(OE_FAILURE);
    }

#if defined(__linux__)
    AddressOfNames = *exd->AddressOfNames;
    AddressOfFunctions = *exd->AddressOfFunctions;
#elif defined(_WIN32)
    AddressOfNames = exd->AddressOfNames;
    AddressOfFunctions = exd->AddressOfFunctions;
#else
#error "unsupported"
#endif

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)exd->NumberOfNames * sizeof(uint32_t) + AddressOfNames >
        image->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    if ((uint64_t)exd->NumberOfFunctions * sizeof(uint32_t) +
            AddressOfFunctions >
        image->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* allocate ecall array (might allocated more than needed if there are
     * exports not in .ecall section) */
    enclave->ecalls =
        (ECallNameAddr*)malloc(exd->NumberOfFunctions * sizeof(ECallNameAddr));
    if (!enclave->ecalls)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    name_table = (uint32_t*)(image_base + AddressOfNames);
    func_table = (uint32_t*)(image_base + AddressOfFunctions);

    for (i = 0; i < exd->NumberOfFunctions; i++)
    {
        if (func_table[i] - image->ecall_rva < image->ecall_section_size)
        {
            ecall = &enclave->ecalls[enclave->num_ecalls];
            ecall->name = oe_strdup(image_base + name_table[i]);
            if (!ecall->name)
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }
            ecall->code = StrCode(ecall->name, strlen(ecall->name));
            ecall->vaddr = func_table[i];
            enclave->num_ecalls++;
        }
    }
    result = OE_OK;

done:
    if (OE_OK != result)
    {
        oe_free_enclave_ecalls(enclave);
    }
    return result;
}

static oe_result_t _patch(
    oe_enclave_image_t* image,
    size_t ecall_size,
    size_t enclave_end)
{
    oe_sgx_enclave_properties_t* oeprops;

    oeprops =
        (oe_sgx_enclave_properties_t*)(image->image_base + image->oeinfo_rva);

    assert((image->image_size & ((uint64_t)OE_PAGE_SIZE - 1)) == 0);
    assert((image->oeinfo_rva & ((uint64_t)OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_end & (OE_PAGE_SIZE - 1)) == 0);
    assert((ecall_size & (OE_PAGE_SIZE - 1)) == 0);

    oeprops->image_info.enclave_size = enclave_end;
    oeprops->image_info.oeinfo_rva = image->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Unlike Linux, reloc is in the image itself */
    oeprops->image_info.reloc_rva = image->u.pe.reloc_rva;
    oeprops->image_info.reloc_size = image->reloc_size;

    /* ecal right after image */
    oeprops->image_info.ecall_rva = image->image_size;
    oeprops->image_info.ecall_size = ecall_size;

    /* heap right after ecall */
    oeprops->image_info.heap_rva = oeprops->image_info.ecall_rva + ecall_size;

    /* Clear the hash when taking the measure */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    return OE_OK;
}

oe_result_t oe_load_pe_enclave_image(
    const char* path,
    oe_enclave_image_t* image)
{
    oe_result_t result = OE_UNEXPECTED;
    PIMAGE_NT_HEADERS nt_header;
    PIMAGE_SECTION_HEADER section_hdr;
    const IMAGE_DATA_DIRECTORY* idd;
    uint32_t i;

    memset(image, 0, sizeof(oe_enclave_image_t));
    image->type = OE_IMAGE_TYPE_PE;
    image->u.pe.module =
        LoadLibraryExA(path, 0, LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    if (!image->u.pe.module)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* get image base from module by zeroing out the bottom bits */
    image->image_base =
        (char*)((uint64_t)image->u.pe.module & (uint64_t)-OE_PAGE_SIZE);

    /* get nt header */
    OE_CHECK(_oe_get_nt_header(image->image_base, &nt_header));

    image->u.pe.nt_header = nt_header;
    image->image_size = nt_header->OptionalHeader.SizeOfImage;
    image->entry_rva = nt_header->OptionalHeader.AddressOfEntryPoint;

    /* image size must be multiple of pages */
    if (image->image_size & (OE_PAGE_SIZE - 1))
    {
        OE_RAISE(OE_FAILURE);
    }

    /* find the reloc rva/size */
    idd = &nt_header->OptionalHeader
               .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)idd->VirtualAddress + idd->Size > image->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    image->u.pe.reloc_rva = idd->VirtualAddress;
    image->reloc_size = idd->Size;

    /* change protection to r/w */
    if (!VirtualProtect(
            image->image_base, image->image_size, PAGE_READWRITE, &i))
    {
        OE_RAISE(OE_FAILURE);
    }

    /* validate image  - section must be sorted by rva and not overlap */
    section_hdr = IMAGE_FIRST_SECTION(nt_header);
    for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_hdr++)
    {
        uint64_t next_section_start;
        if ((section_hdr->VirtualAddress == 0) ||
            (section_hdr->Misc.VirtualSize == 0) ||
            /* section base address must be page-algined */
            (section_hdr->VirtualAddress & (OE_PAGE_SIZE - 1)))
        {
            OE_RAISE(OE_FAILURE);
        }

        /* sections must not overlap */
        next_section_start = ((i + 1) < nt_header->FileHeader.NumberOfSections)
                                 ? section_hdr[1].VirtualAddress
                                 : image->image_size;

        /* cast to uint64_t to avoid arithmetic overflow */
        if ((uint64_t)section_hdr->VirtualAddress +
                section_hdr->Misc.VirtualSize >
            next_section_start)
            OE_RAISE_MSG(
                OE_FAILURE,
                "VirtualAddress expands over to the next section",
                NULL);

        if (strcmp((const char*)section_hdr->Name, ".text") == 0)
        {
            image->text_rva = section_hdr->VirtualAddress;
        }

        if (strcmp((const char*)section_hdr->Name, ".oeinfo") == 0)
        {
            image->oeinfo_rva = section_hdr->VirtualAddress;
            image->oeinfo_file_pos = section_hdr->PointerToRawData;
        }

        if (strcmp((const char*)section_hdr->Name, ".ecall") == 0)
        {
            image->ecall_rva = section_hdr->VirtualAddress;
            image->ecall_section_size = section_hdr->Misc.VirtualSize;
        }
    }

    /* fail if no .text section */
    if (image->text_rva == 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    image->type = OE_IMAGE_TYPE_PE;
    image->calculate_size = _calculate_size;
    image->add_pages = _add_pages;
    image->patch = _patch;
    image->build_ecall_array = _build_ecall_array;
    image->sgx_load_enclave_properties = _sgx_load_enclave_properties;
    image->sgx_update_enclave_properties = _sgx_update_enclave_properties;
    image->unload = _unload;

    result = OE_OK;

done:
    if (OE_OK != result)
    {
        _unload(image);
    }
    return result;
}
