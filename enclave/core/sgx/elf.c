// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "elf.h"
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

static int _elf64_test_header(const elf64_ehdr_t* ehdr)
{
    if (!ehdr)
        return -1;

    if (ehdr->e_ident[EI_MAG0] != 0x7f)
        return -1;

    if (ehdr->e_ident[EI_MAG1] != 'E')
        return -1;

    if (ehdr->e_ident[EI_MAG2] != 'L')
        return -1;

    if (ehdr->e_ident[EI_MAG3] != 'F')
        return -1;

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return -1;

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;

    if (ehdr->e_machine != EM_X86_64)
        return -1;

    if (ehdr->e_ehsize != sizeof(elf64_ehdr_t))
        return -1;

    if (ehdr->e_phentsize != sizeof(elf64_phdr_t))
        return -1;

    if (ehdr->e_shentsize != sizeof(elf64_shdr_t))
        return -1;

    /* If there is no section header table, then the index should be 0. */
    if (ehdr->e_shnum == 0 && ehdr->e_shstrndx != 0)
        return -1;

    /* If there is a section header table, then the index shouldn't overrun. */
    if (ehdr->e_shnum > 0 && ehdr->e_shstrndx >= ehdr->e_shnum)
        return -1;

    return 0;
}

oe_result_t oe_get_elf_info(uint8_t* module_base, oe_elf_info_t* elf_info)
{
    oe_result_t result = OE_UNEXPECTED;
    elf64_ehdr_t* ehdr = (elf64_ehdr_t*)module_base;
    elf64_rela_t* relocs = 0;
    uint64_t num_relocs = 0;
    uint64_t load_end_offset = 0;
    elf64_phdr_t* phdrs = NULL;

    memset(elf_info, 0, sizeof(*elf_info));
    if (_elf64_test_header(ehdr) != 0)
        OE_RAISE(OE_FAILURE);

    // Iterate through the program headers and gather relevant information.
    phdrs = (elf64_phdr_t*)(module_base + ehdr->e_phoff);

    for (int32_t i = 0; i < ehdr->e_phnum; ++i)
    {
        elf64_phdr_t* phdr = &phdrs[i];
        if (phdr->p_type == PT_TLS)
        {
            elf_info->tdata_align = elf_info->tbss_align = phdr->p_align;
            elf_info->tdata_rva = phdr->p_vaddr;
            elf_info->tdata_size = phdr->p_filesz;
            elf_info->tbss_size = phdr->p_memsz - phdr->p_filesz;
        }

        {
            uint64_t end = phdr->p_vaddr + phdr->p_memsz;
            if (end > load_end_offset)
                load_end_offset = end;
        }
    }

    elf_info->reloc_rva =
        oe_round_up_to_multiple(load_end_offset, OE_PAGE_SIZE);

    relocs = (elf64_rela_t*)(module_base + elf_info->reloc_rva);

    while (relocs[num_relocs].r_offset != 0)
        ++num_relocs;
    elf_info->num_relocs = num_relocs;

    result = OE_OK;
done:
    return result;
}
