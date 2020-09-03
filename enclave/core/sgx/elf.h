// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_ELF_H
#define _OE_ENCLAVE_ELF_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _elf_info
{
    uint64_t tdata_rva;
    uint64_t tdata_size;
    uint64_t tdata_align;
    uint64_t tbss_size;
    uint64_t tbss_align;
    uint64_t reloc_rva;
    uint64_t num_relocs;
} oe_elf_info_t;

oe_result_t oe_get_elf_info(uint8_t* module_base, oe_elf_info_t* elf_info);

OE_EXTERNC_END

#endif // _OE_ENCLAVE_ELF_H
