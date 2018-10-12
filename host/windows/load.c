// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

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
#include <windows.h>
#include "../enclave.h"
#include "../memalign.h"
#include "../sgxload.h"
#include "../strings.h"

oe_result_t _oe_get_nt_header(char* image_base, PIMAGE_NT_HEADERS* nt_header)
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

oe_result_t oe_sgx_load_properties(
    const oe_enclave_image_t* oeimage,
    const char* sectionName, // unused
    oe_sgx_enclave_properties_t* properties)
{
    assert(oeimage);
    assert(oeimage->oeinfo_rva);
    assert(properties);

    memcpy(
        properties,
        oeimage->image_base + oeimage->oeinfo_rva,
        sizeof(*properties));
    return OE_OK;
}

oe_result_t oe_sgx_update_enclave_properties(
    const oe_enclave_image_t* oeimage,
    const char* sectionName, // unused
    const oe_sgx_enclave_properties_t* properties)
{
    assert(oeimage);
    assert(oeimage->oeinfo_rva);
    assert(properties);

    memcpy(
        oeimage->image_base + oeimage->oeinfo_rva,
        properties,
        sizeof(*properties));
    return OE_OK;
}

oe_result_t _oe_load_enclave_image(
    const char* path,
    oe_enclave_image_t* oeimage)
{
    oe_result_t result = OE_UNEXPECTED;
    PIMAGE_NT_HEADERS nt_header;
    PIMAGE_SECTION_HEADER section_hdr;
    const IMAGE_DATA_DIRECTORY* idd;
    uint32_t i;

    memset(oeimage, 0, sizeof(oe_enclave_image_t));
    oeimage->module = LoadLibraryExA(path, 0, LOAD_LIBRARY_AS_IMAGE_RESOURCE);

    if (!oeimage->module)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* get image base from module by zeroing out the bottom bits */
    oeimage->image_base = (char*)((uint64_t)oeimage->module & -OE_PAGE_SIZE);

    /* get nt header */
    OE_CHECK(_oe_get_nt_header(oeimage->image_base, &nt_header));

    oeimage->nt_header = nt_header;
    oeimage->image_size = nt_header->OptionalHeader.SizeOfImage;
    oeimage->entry_rva = nt_header->OptionalHeader.AddressOfEntryPoint;

    /* image size must be multiple of pages */
    if (oeimage->image_size & (OE_PAGE_SIZE - 1))
    {
        OE_RAISE(OE_FAILURE);
    }

    /* find the reloc rva/size */
    idd = &nt_header->OptionalHeader
               .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)idd->VirtualAddress + idd->Size > oeimage->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    oeimage->reloc_rva = idd->VirtualAddress;
    oeimage->reloc_size = idd->Size;

    /* change protection to r/w */
    if (!VirtualProtect(
            oeimage->image_base, oeimage->image_size, PAGE_READWRITE, &i))
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
                                 : oeimage->image_size;

        /* cast to uint64_t to avoid arithmetic overflow */
        if ((uint64_t)section_hdr->VirtualAddress +
                section_hdr->Misc.VirtualSize >
            next_section_start)
        {
            OE_RAISE(OE_FAILURE);
        }

        if (strcmp(section_hdr->Name, ".text") == 0)
        {
            oeimage->text_rva = section_hdr->VirtualAddress;
        }

        if (strcmp(section_hdr->Name, ".oeinfo") == 0)
        {
            oeimage->oeinfo_rva = section_hdr->VirtualAddress;
            oeimage->oeinfo_file_pos = section_hdr->PointerToRawData;
        }

        if (strcmp(section_hdr->Name, ".ecall") == 0)
        {
            oeimage->ecall_rva = section_hdr->VirtualAddress;
            oeimage->ecall_section_size = section_hdr->Misc.VirtualSize;
        }
    }

    /* fail if no .text section */
    if (oeimage->text_rva == 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:
    if (OE_OK != result)
    {
        _oe_unload_enclave_image(oeimage);
    }
    return result;
}

oe_result_t _oe_unload_enclave_image(oe_enclave_image_t* oeimage)
{
    if (oeimage->module)
    {
        FreeLibrary((HMODULE)oeimage->module);
    }
    memset(oeimage, 0, sizeof(oe_enclave_image_t));
    return OE_OK;
}

oe_result_t _oe_calculate_image_size(
    const oe_enclave_image_t* oeimage,
    size_t* image_size)
{
    oe_result_t result = OE_UNEXPECTED;

    assert(oeimage && image_size);

    *image_size = oeimage->image_size;
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
    for (i = 0; i < section_hdr->Misc.VirtualSize; i += OE_PAGE_SIZE)
    {
        uint64_t offset = section_hdr->VirtualAddress + i;
        OE_CHECK(
            oe_sgx_load_enclave_data(
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
oe_result_t _oe_add_image_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    oe_enclave_image_t* oeimage,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)oeimage->nt_header;
    PIMAGE_SECTION_HEADER section_hdr;
    size_t i;

    assert(context);
    assert(enclave);
    assert(oeimage);
    assert(vaddr && (*vaddr == 0));
    assert((oeimage->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert(enclave->size > oeimage->image_size);

    section_hdr = IMAGE_FIRST_SECTION(nt_header);

    /* Add image header as r/o pages */
    for (i = 0; i < section_hdr->VirtualAddress; i += OE_PAGE_SIZE)
    {
        OE_CHECK(
            oe_sgx_load_enclave_data(
                context,
                enclave->addr,
                enclave->addr + i,
                (uint64_t)oeimage->image_base + i,
                SGX_SECINFO_R,
                true));
    }

    /* Add all the sections. */
    for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_hdr++)
    {
        OE_CHECK(
            _add_section_pages(
                context, enclave->addr, section_hdr, oeimage->image_base));
    }

    *vaddr = oeimage->image_size;
    result = OE_OK;

done:
    return result;
}

oe_result_t _oe_build_ecall_array(
    oe_enclave_t* enclave,
    oe_enclave_image_t* oeimage)
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

    assert(enclave);
    assert(oeimage);

    image_base = oeimage->image_base;
    nt_header = (const IMAGE_NT_HEADERS*)oeimage->nt_header;
    exh =
        &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)exh->VirtualAddress + exh->Size > oeimage->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }

    exd = (const IMAGE_EXPORT_DIRECTORY*)(image_base + exh->VirtualAddress);

    /* All exports must be named */
    if (exd->NumberOfFunctions != exd->NumberOfNames)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* cast to uint64_t to avoid arithmetic overflow */
    if ((uint64_t)exd->NumberOfNames * sizeof(uint32_t) + exd->AddressOfNames >
        oeimage->image_size)
    {
        OE_RAISE(OE_FAILURE);
    }
    if ((uint64_t)exd->NumberOfFunctions * sizeof(uint32_t) +
            exd->AddressOfFunctions >
        oeimage->image_size)
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

    name_table = (uint32_t*)(image_base + exd->AddressOfNames);
    func_table = (uint32_t*)(image_base + exd->AddressOfFunctions);

    for (i = 0; i < exd->NumberOfFunctions; i++)
    {
        if (func_table[i] - oeimage->ecall_rva < oeimage->ecall_section_size)
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
        _oe_free_enclave_ecalls(enclave);
    }
    return result;
}

oe_result_t _oe_patch_image(
    oe_enclave_image_t* oeimage,
    size_t ecall_size,
    size_t enclave_end)

{
    oe_sgx_enclave_properties_t* oeprops;

    oeprops =
        (oe_sgx_enclave_properties_t*)(oeimage->image_base + oeimage->oeinfo_rva);

    assert((oeimage->image_size & (OE_PAGE_SIZE - 1)) == 0);
    assert((oeimage->oeinfo_rva & (OE_PAGE_SIZE - 1)) == 0);
    assert((enclave_end & (OE_PAGE_SIZE - 1)) == 0);
    assert((ecall_size & (OE_PAGE_SIZE - 1)) == 0);

    oeprops->image_info.enclave_size = enclave_end;
    oeprops->image_info.oeinfo_rva = oeimage->oeinfo_rva;
    oeprops->image_info.oeinfo_size = sizeof(oe_sgx_enclave_properties_t);

    /* Unlike Linux, reloc is in the image itself */
    oeprops->image_info.reloc_rva = oeimage->reloc_rva;
    oeprops->image_info.reloc_size = oeimage->reloc_size;

    /* ecal right after image */
    oeprops->image_info.ecall_rva = oeimage->image_size;
    oeprops->image_info.ecall_size = ecall_size;

    /* heap right after ecall */
    oeprops->image_info.heap_rva = oeprops->image_info.ecall_rva + ecall_size;

    /* Clear the hash when taking the measure */
    memset(oeprops->sigstruct, 0, sizeof(oeprops->sigstruct));

    return OE_OK;
}
