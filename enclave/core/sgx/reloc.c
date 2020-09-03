// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include "elf.h"
#include "init.h"

// Declare just for assertion. Temporary code.
extern uint64_t _reloc_rva, _reloc_size, _tdata_rva, _tdata_size, _tdata_align,
    _tbss_size, _tbss_align;

// Before reloations, _enclave_base will contain its own RVA, and
// subtracting its address from its value will give the actual enclave base
// address.
uint8_t* _enclave_base = (uint8_t*)&_enclave_base;

/*
**==============================================================================
**
** oe_apply_relocations()
**
**     Apply symbol relocations from the relocation pages, whose content
**     was copied from the ELF file during loading. These relocations are
**     included in the enclave signature (MRENCLAVE).
**
**==============================================================================
*/

bool oe_apply_relocations(void)
{
    const elf64_rela_t* relocs = (const elf64_rela_t*)__oe_get_reloc_base();
    size_t nrelocs = __oe_get_reloc_size() / sizeof(elf64_rela_t);
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
    oe_elf_info_t elf_info = {0};
    size_t i = 0;

    // Before relocation, compute the enclave base address.
    _enclave_base = (uint8_t*)&_enclave_base - (uint64_t)_enclave_base;
    if (baseaddr != _enclave_base)
        return false;

    if (oe_get_elf_info((uint8_t*)baseaddr, &elf_info) != OE_OK)
        return false;

    if (elf_info.reloc_rva != _reloc_rva || elf_info.tdata_rva != _tdata_rva ||
        elf_info.tdata_size != _tdata_size ||
        elf_info.tbss_size != _tbss_size ||
        (elf_info.tdata_align != _tdata_align &&
         elf_info.tbss_align != _tbss_align))
        return false;

    for (i = 0; i < nrelocs; i++)
    {
        const elf64_rela_t* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);
        if ((void*)dest == &_enclave_base)
            continue;

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        if (reloc_type == R_X86_64_RELATIVE)
        {
            *dest = (uint64_t)(baseaddr + p->r_addend);
        }
    }

    if (baseaddr != _enclave_base)
        return false;

    if (i != elf_info.num_relocs)
        return false;

    return true;
}
