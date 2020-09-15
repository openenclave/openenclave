// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/utils.h>
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

static uint64_t _apply_relocations(
    const uint8_t* baseaddr,
    const elf64_rela_t* relocs,
    size_t nrelocs)
{
    for (size_t i = 0; i < nrelocs; i++)
    {
        const elf64_rela_t* p = &relocs[i];

        /* If zero-padded bytes reached need to skip to next
         * page boundary and check for relocs for next image.
         *
         * TODO: Fix relocs to only zero pad on final reloc
         * section */
        if (p->r_offset == 0)
        {
            return oe_round_up_to_page_size((uint64_t)p);
        }

        /* Compute address of reference to be relocated.
         * The target offset for the fixup should have been fixed during
         * the dynamic binding at load time. */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        /* Relocate the reference */
        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);
        switch (reloc_type)
        {
            case R_X86_64_RELATIVE:
            {
                *dest = (uint64_t)(baseaddr + p->r_addend);
                break;
            }
            case R_X86_64_JUMP_SLOT:
            case R_X86_64_GLOB_DAT:
            {
                /* OE SDK overloads the addend but this should be usually the
                 * symbol address */
                int64_t addend = p->r_addend;
                if (addend)
                {
                    *dest = (uint64_t)(baseaddr + p->r_addend);
                }
                break;
            }
            case R_X86_64_TPOFF64:
            {
                /* TODO: Thread local relocation RHS does not depend on base
                 * address and is a precomputed constant value. Therefore the
                 * loader itself can apply the relocation before measurement.
                 * NOTE: OE SDK performs this relocation differently.
                 * See loadelf.c */
                *dest = (uint64_t)p->r_addend;
                break;
            }
        }
    }

    return (uint64_t)relocs + (nrelocs * sizeof(elf64_rela_t));
}

bool oe_apply_relocations(void)
{
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
    uint64_t relocs = (uint64_t)__oe_get_reloc_base();
    uint64_t reloc_end = relocs + __oe_get_reloc_size();

    while (relocs < reloc_end)
    {
        size_t nrelocs = (reloc_end - relocs) / sizeof(elf64_rela_t);
        relocs =
            _apply_relocations(baseaddr, (const elf64_rela_t*)relocs, nrelocs);
    }

    return true;
}
