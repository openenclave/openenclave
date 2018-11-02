// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <windows.h>
#include "../init.h"

/*
 *  _reloc_bias is used to calculate relocation difference *BEFORE*
 *  relocation.
 *
 *  Since _reloc_bias hasn't been relocated, it contains the original value.
 *  Therefore, before relocation,
 *      relocation_diff = (uint64_t)&_reloc_bias - _reloc_bias;
 *
 *  because &_reloc_bias is pc-relative and will be the post-relocation
 *  value.
 */
static volatile uint64_t _reloc_bias = (uint64_t)&_reloc_bias;

static uint64_t _next_reloc_addr(uint64_t reloc_addr)
{
    const IMAGE_BASE_RELOCATION* reloc =
        (const IMAGE_BASE_RELOCATION*)reloc_addr;
    return (reloc_addr + reloc->SizeOfBlock);
}

static bool _relocate_one_block(
    uint64_t image_base,
    uint64_t reloc_addr,
    uint64_t reloc_diff)
{
    const IMAGE_BASE_RELOCATION* reloc =
        (const IMAGE_BASE_RELOCATION*)reloc_addr;
    PUSHORT reloc_ptr = (PUSHORT)(reloc + 1);
    PUSHORT reloc_end = (PUSHORT)(reloc_addr + reloc->SizeOfBlock);
    uint64_t block_base_addr = image_base + reloc->VirtualAddress;
    bool result = true;

    for (; reloc_ptr < reloc_end; reloc_ptr++)
    {
        uint64_t fixup_addr = block_base_addr + (*reloc_ptr & 0xfff);

        /* All relocation must be 64-bit relocation */
        if (IMAGE_REL_BASED_DIR64 != (*reloc_ptr >> 12))
        {
            result = false;
            break;
        }

        *(uint64_t __unaligned*)fixup_addr += reloc_diff;
    }
    return result;
}

/*
**==============================================================================
**
** oe_apply_relocations()
**
**     Apply relocations from PE Enclave image.
**
**==============================================================================
*/

bool oe_apply_relocations(void)
{
    uint64_t image_base = (uint64_t)__oe_get_enclave_base();
    uint64_t reloc_addr = (uint64_t)__oe_get_reloc_base();
    uint64_t reloc_end = reloc_addr + __oe_get_reloc_size();
    uint64_t reloc_diff = (uint64_t)&_reloc_bias - _reloc_bias;
    bool result = true;

    while (reloc_addr < reloc_end)
    {
        result = _relocate_one_block(image_base, reloc_addr, reloc_diff);
        if (!result)
        {
            break;
        }
        reloc_addr = _next_reloc_addr(reloc_addr);
    }

    /*
     *  _reloc_bias must be allocated after relocation. Therefore it must
     *  be equal to its address.
     */

    return result && (((uint64_t)&_reloc_bias - _reloc_bias) == 0);
}
