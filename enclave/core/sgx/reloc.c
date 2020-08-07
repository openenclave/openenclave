// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include "init.h"

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
    /* TODO: relocs still only works for single dependency */
    const elf64_rela_t* relocs = (const elf64_rela_t*)__oe_get_reloc_base();
    size_t nrelocs = __oe_get_reloc_size() / sizeof(elf64_rela_t);
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

    for (size_t i = 0; i < nrelocs; i++)
    {
        const elf64_rela_t* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        switch (reloc_type)
        {
            case R_X86_64_RELATIVE:
            {
                *dest = (uint64_t)(baseaddr + p->r_addend);
                break;
            }
            case R_X86_64_GLOB_DAT:
            {
                /* OE SDK overloads the addend but this should be usually the
                 * symbol address */
                int64_t addend = p->r_addend;
                if (addend)
                {
                    *dest = (uint64_t)(baseaddr + p->r_addend);
                }
            }
        }
    }
    return true;
}
