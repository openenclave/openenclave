// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <ctype.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/load.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/utils.h>
#include <stdio.h>
#include <string.h>
#include "fopen.h"
#include "strings.h"

#define GOTO(LABEL)                                            \
    do                                                         \
    {                                                          \
        fprintf(stderr, "GOTO: %s(%u)\n", __FILE__, __LINE__); \
        goto LABEL;                                            \
    } while (0)

OE_INLINE bool _Ok(const Elf64* elf)
{
    return (!elf || elf->magic != ELF_MAGIC) ? false : true;
}

static Elf64_Ehdr* _GetHeader(const Elf64* elf)
{
    return (Elf64_Ehdr*)elf->data;
}

static Elf64_Shdr* _GetShdr(const Elf64* elf, size_t index)
{
    Elf64_Shdr* shdrs =
        (Elf64_Shdr*)((uint8_t*)elf->data + _GetHeader(elf)->e_shoff);
    return &shdrs[index];
}

static Elf64_Phdr* _GetPhdr(const Elf64* elf, size_t index)
{
    Elf64_Phdr* phdrs =
        (Elf64_Phdr*)((uint8_t*)elf->data + _GetHeader(elf)->e_phoff);
    return &phdrs[index];
}

static void* _GetSection(const Elf64* elf, size_t index)
{
    const Elf64_Shdr* sh = _GetShdr(elf, index);
    return sh->sh_type == PT_NULL ? NULL : (uint8_t*)elf->data + sh->sh_offset;
}

static void* _GetSegment(const Elf64* elf, size_t index)
{
    const Elf64_Phdr* ph = _GetPhdr(elf, index);
    return ph->p_type == PT_NULL ? NULL : (uint8_t*)elf->data + ph->p_offset;
}

Elf64_Ehdr* Elf64_GetHeader(const Elf64* elf)
{
    return _GetHeader(elf);
}

void* Elf64_GetSegment(const Elf64* elf, size_t index)
{
    if (!_Ok(elf) || index >= _GetHeader(elf)->e_phnum)
        return NULL;

    return _GetSegment(elf, index);
}

Elf64_Shdr* Elf64_GetSectionHeader(const Elf64* elf, size_t index)
{
    if (!_Ok(elf) || index >= _GetHeader(elf)->e_phnum)
        return NULL;

    return _GetShdr(elf, index);
}

Elf64_Phdr* Elf64_GetProgramHeader(const Elf64* elf, size_t index)
{
    if (!_Ok(elf) || index >= _GetHeader(elf)->e_shnum)
        return NULL;

    return _GetPhdr(elf, index);
}

int Elf64_TestHeader(const Elf64_Ehdr* ehdr)
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

    if (ehdr->e_machine != EM_X86_64)
        return -1;

    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr))
        return -1;

    return 0;
}

/* Add adjustment value to all section offsets greater than OFFSET */
static void _AdjustSectionHeaderOffsets(
    Elf64* elf,
    size_t offset,
    ssize_t adjustment)
{
    size_t i;
    Elf64_Ehdr* ehdr = _GetHeader(elf);

    /* Adjust section header offset */
    if (ehdr->e_shoff >= offset)
        ehdr->e_shoff += adjustment;

    Elf64_Shdr* shdrs = (Elf64_Shdr*)((uint8_t*)elf->data + ehdr->e_shoff);

    /* Adjust offsets to individual headers */
    for (i = 0; i < ehdr->e_shnum; i++)
    {
        Elf64_Shdr* sh = &shdrs[i];

        if (sh->sh_offset >= offset)
            sh->sh_offset += adjustment;
    }
}

static int _ResetBuffer(
    Elf64* elf,
    mem_t* mem,
    size_t offset,
    ssize_t adjustment)
{
    /* Reset the pointers to the ELF image */
    elf->data = mem_mutable_ptr(mem);
    elf->size = mem_size(mem);

    /* Adjust section header offsets greater than offset */
    _AdjustSectionHeaderOffsets(elf, offset, adjustment);

    return 0;
}

int Elf64_Load(const char* path, Elf64* elf)
{
    int rc = -1;
    FILE* is = NULL;

    if (elf)
        memset(elf, 0, sizeof(Elf64));

    if (!path || !elf)
        goto done;

    /* Open input file */
    if (OE_Fopen(&is, path, "rb") != 0)
        goto done;

    /* Get the size of this file */
    fseek(is, 0, SEEK_END);
    elf->size = (size_t)ftell(is);

    /* Allocate the data to hold this image */
    if (!(elf->data = malloc(elf->size)))
        goto done;

    /* Read the file into memory */
    rewind(is);
    if (fread(elf->data, 1, elf->size, is) != elf->size)
        goto done;

    /* Set the magic number */
    elf->magic = ELF_MAGIC;

    rc = 0;

done:

    if (is)
        fclose(is);

    if (rc != 0)
    {
        free(elf->data);
        memset(elf, 0, sizeof(Elf64));
    }

    return rc;
}

int Elf64_Unload(Elf64* elf)
{
    int rc = -1;

    if (!_Ok(elf))
        goto done;

    free(elf->data);

    rc = 0;

done:

    return rc;
}

static size_t _FindShdr(const Elf64* elf, const char* name)
{
    size_t result = (size_t)-1;
    size_t i;

    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            result = i;
            goto done;
        }
    }

done:
    return result;
}

const char* Elf64_GetStringFromStrtab(const Elf64* elf, Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!_Ok(elf))
        goto done;

    if ((index = _FindShdr(elf, ".strtab")) == (size_t)-1)
        goto done;

    if (index > _GetHeader(elf)->e_shnum)
        goto done;

    sh = _GetShdr(elf, index);

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)_GetSection(elf, index) + offset;

done:
    return result;
}

const char* Elf64_GetStringFromShstrtab(const Elf64* elf, Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!_Ok(elf))
        goto done;

    index = _GetHeader(elf)->e_shstrndx;

    if (index > _GetHeader(elf)->e_shnum)
        goto done;

    sh = _GetShdr(elf, index);

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)_GetSection(elf, index) + offset;

done:
    return result;
}

int Elf64_FindSymbolByName(const Elf64* elf, const char* name, Elf64_Sym* sym)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
#if 1
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;
#else
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;
#endif

    if (!_Ok(elf) || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = _GetShdr(elf, index)))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)_GetSection(elf, index)))
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const Elf64_Sym* p = &symtab[i];
        const char* s;

        /* Skip empty names */
        if (p->st_name == 0)
            continue;

        /* If illegal name */
        if (!(s = Elf64_GetStringFromStrtab(elf, p->st_name)))
            goto done;

        /* If found */
        if (strcmp(name, s) == 0)
        {
            *sym = *p;
            rc = 0;
            goto done;
        }
    }

done:
    return rc;
}

const char* Elf64_GetStringFromDynstr(const Elf64* elf, Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!_Ok(elf))
        goto done;

    if ((index = _FindShdr(elf, ".dynstr")) == (size_t)-1)
        goto done;

    if (index > _GetHeader(elf)->e_shnum)
        goto done;

    sh = _GetShdr(elf, index);

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)_GetSection(elf, index) + offset;

done:
    return result;
}

int Elf64_FindDynamicSymbolByName(
    const Elf64* elf,
    const char* name,
    Elf64_Sym* sym)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;

    if (!_Ok(elf) || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = _GetShdr(elf, index)))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)_GetSection(elf, index)))
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const Elf64_Sym* p = &symtab[i];
        const char* s;

        /* Skip empty names */
        if (p->st_name == 0)
            continue;

        /* If illegal name */
        if (!(s = Elf64_GetStringFromDynstr(elf, p->st_name)))
            goto done;

        /* If found */
        if (strcmp(name, s) == 0)
        {
            *sym = *p;
            rc = 0;
            goto done;
        }
    }

done:
    return rc;
}

int Elf64_FindSymbolByAddress(
    const Elf64* elf,
    Elf64_Addr addr,
    unsigned int type,
    Elf64_Sym* sym)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
#if 1
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;
#else
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;
#endif

    if (!_Ok(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = _GetShdr(elf, index)))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)_GetSection(elf, index)))
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const Elf64_Sym* p = &symtab[i];
        unsigned int stt = (p->st_info & 0x0F);

        if (stt != type)
            continue;

        if (p->st_value == addr)
        {
            *sym = *p;
            rc = 0;
            goto done;
        }
    }

done:
    return rc;
}

int Elf64_FindDynamicSymbolByAddress(
    const Elf64* elf,
    Elf64_Addr addr,
    unsigned int type,
    Elf64_Sym* sym)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
#if 0
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;
#else
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;
#endif

    if (!_Ok(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = _GetShdr(elf, index)))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)_GetSection(elf, index)))
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const Elf64_Sym* p = &symtab[i];
        unsigned int stt = (p->st_info & 0x0F);

        if (stt != type)
            continue;

        if (p->st_value == addr)
        {
            *sym = *p;
            rc = 0;
            goto done;
        }
    }

done:
    return rc;
}

void Elf64_DumpHeader(const Elf64_Ehdr* h)
{
    if (!h || Elf64_TestHeader(h) != 0)
        return;

    printf("=== Elf64_Ehdr:\n");

    /* Print e_ident[] */
    printf("e_ident[EI_MAG0]=%02x\n", h->e_ident[EI_MAG0]);
    printf("e_ident[EI_MAG1]=%c\n", h->e_ident[EI_MAG1]);
    printf("e_ident[EI_MAG2]=%c\n", h->e_ident[EI_MAG2]);
    printf("e_ident[EI_MAG3]=%c\n", h->e_ident[EI_MAG3]);

    switch (h->e_ident[EI_CLASS])
    {
        case ELFCLASSNONE:
            printf("e_ident[EI_CLASS]=ELFCLASSNONE\n");
            break;
        case ELFCLASS32:
            printf("e_ident[EI_CLASS]=ELFCLASS32\n");
            break;
        case ELFCLASS64:
            printf("e_ident[EI_CLASS]=ELFCLASS64\n");
            break;
        default:
            printf("e_ident[EI_CLASS]=%02x\n", h->e_ident[EI_CLASS]);
            break;
    }

    switch (h->e_ident[EI_DATA])
    {
        case ELFDATANONE:
            printf("e_ident[EI_DATA]=ELFDATANONE\n");
            break;
        case ELFDATA2LSB:
            printf("e_ident[EI_DATA]=ELFDATA2LSB\n");
            break;
        case ELFDATA2MSB:
            printf("e_ident[EI_DATA]=ELFDATA2MSB\n");
            break;
        default:
            printf("e_ident[EI_DATA]=%02x\n", h->e_ident[EI_DATA]);
            break;
    }

    printf("e_ident[EI_VERSION]=%02x\n", h->e_ident[EI_VERSION]);
    printf("e_ident[EI_PAD]=%02x\n", h->e_ident[EI_PAD]);

    switch (h->e_type)
    {
        case ET_NONE:
            printf("e_type=ET_NONE\n");
            break;
        case ET_REL:
            printf("e_type=ET_REL\n");
            break;
        case ET_EXEC:
            printf("e_type=ET_EXEC\n");
            break;
        case ET_DYN:
            printf("e_type=ET_DYN\n");
            break;
        case ET_CORE:
            printf("e_type=ET_CORE\n");
            break;
        case ET_LOPROC:
            printf("e_type=ET_LOPROC\n");
            break;
        case ET_HIPROC:
            printf("e_type=ET_HIPROC\n");
            break;
        default:
            printf("e_type=%02x\n", h->e_type);
            break;
    }

    switch (h->e_machine)
    {
        case EM_NONE:
            printf("e_machine=EM_NONE\n");
            break;
        case EM_M32:
            printf("e_machine=EM_M32\n");
            break;
        case EM_SPARC:
            printf("e_machine=EM_SPARC\n");
            break;
        case EM_386:
            printf("e_machine=EM_386\n");
            break;
        case EM_68K:
            printf("e_machine=EM_68K\n");
            break;
        case EM_88K:
            printf("e_machine=EM_88K\n");
            break;
        case EM_860:
            printf("e_machine=EM_860\n");
            break;
        case EM_MIPS:
            printf("e_machine=EM_MIPS\n");
            break;
        case EM_X86_64:
            printf("e_machine=EM_X86_64\n");
            break;
        default:
            printf("e_machine=%u\n", h->e_machine);
            break;
    }

    printf("e_version=%u\n", h->e_version);
    printf("e_entry=%llx\n", OE_LLX(h->e_entry));
    printf("e_phoff=%llu\n", OE_LLU(h->e_phoff));
    printf("e_shoff=%llu\n", OE_LLU(h->e_shoff));
    printf("e_flags=%u\n", h->e_flags);
    printf("e_ehsize=%u\n", h->e_ehsize);
    printf("e_phentsize=%u\n", h->e_phentsize);
    printf("e_phnum=%u\n", h->e_phnum);
    printf("e_shentsize=%u\n", h->e_shentsize);
    printf("e_shnum=%u\n", h->e_shnum);
    printf("e_shstrndx=%u\n", h->e_shstrndx);
    printf("\n");
}

void Elf64_DumpShdr(const Elf64_Shdr* sh, size_t index)
{
    if (!sh)
        return;

    printf("=== Elf64_Shdr[%03zu]:\n", index);
    printf("sh_name=%u\n", sh->sh_name);
    printf("sh_type=%u\n", sh->sh_type);

    {
        size_t n = 0;
        printf("sh_flags=");

        if (sh->sh_flags & SHF_ALLOC)
        {
            if (n++)
                printf("|");
            printf("SHF_ALLOC");
        }
        if (sh->sh_flags & SHF_EXECINSTR)
        {
            if (n++)
                printf("|");
            printf("SHF_EXECINSTR");
        }
        if (sh->sh_flags & SHF_MASKOS)
        {
            if (n++)
                printf("|");
            printf("SHF_MASKOS");
        }
        if (sh->sh_flags & SHF_MASKPROC)
        {
            if (n++)
                printf("|");
            printf("SHF_MASKPROC");
        }

        printf("\n");
    }

    printf("sh_addr=%llu\n", OE_LLU(sh->sh_addr));
    printf("sh_offset=%llu\n", OE_LLU(sh->sh_offset));
    printf("sh_size=%llu\n", OE_LLU(sh->sh_size));
    printf("sh_link=%u\n", sh->sh_link);
    printf("sh_info=%u\n", sh->sh_info);
    printf("sh_addralign=%llu\n", OE_LLU(sh->sh_addralign));
    printf("sh_entsize=%llu\n", OE_LLU(sh->sh_entsize));
    printf("\n");
}

static size_t _FindSegmentFor(const Elf64* elf, const Elf64_Shdr* sh)
{
    size_t i = 0;

    for (i = 0; i < _GetHeader(elf)->e_phnum; i++)
    {
        const Elf64_Phdr* ph = _GetPhdr(elf, i);

        if (sh->sh_offset >= ph->p_offset && sh->sh_size <= ph->p_memsz)
            return i;
    }

    return (size_t)-1;
}

int Elf64_DumpSections(const Elf64* elf)
{
    int rc = -1;
    size_t i;

    if (!_Ok(elf))
        goto done;

    if (Elf64_TestHeader(_GetHeader(elf)) != 0)
        goto done;

    puts(
        "Num   Name                     Offset           Size             "
        "Seg ");
    puts(
        "====================================================================="
        "=");

    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        const char* name = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
        size_t segment = _FindSegmentFor(elf, sh);

        printf(
            "[%03zu] %-24s %016llx %016llx ",
            i,
            name,
            OE_LLX(sh->sh_offset),
            OE_LLX(sh->sh_size));

        if (segment == (size_t)-1)
            printf("[???]\n");
        else
            printf("[%03zu]\n", segment);
    }

    printf("\n");

    rc = 0;

done:
    return rc;
}

static void _DumpPhdr(const Elf64_Phdr* ph, size_t index)
{
    if (!ph)
        return;

    printf("=== Elf64_Phdr[%03zu]:\n", index);

    switch (ph->p_type)
    {
        case PT_NULL:
            printf("p_type=PT_NULL\n");
            break;
        case PT_LOAD:
            printf("p_type=PT_LOAD\n");
            break;
        case PT_DYNAMIC:
            printf("p_type=PT_DYNAMIC\n");
            break;
        case PT_INTERP:
            printf("p_type=PT_INTERP\n");
            break;
        case PT_NOTE:
            printf("p_type=PT_NOTE\n");
            break;
        case PT_SHLIB:
            printf("p_type=PT_SHLIB\n");
            break;
        case PT_PHDR:
            printf("p_type=PT_PHDR\n");
            break;
        case PT_LOOS:
            printf("p_type=PT_LOOS\n");
            break;
        default:
        {
            if (ph->p_type >= PT_LOOS && ph->p_type <= PT_HIOS)
                printf("p_type=%08x (OS-specific)\n", ph->p_type);
            else if (ph->p_type >= PT_LOPROC && ph->p_type <= PT_HIPROC)
                printf("p_type=%08x (PROC-specific)\n", ph->p_type);
            else
                printf("p_type=%08x (unknown)\n", ph->p_type);
            break;
        }
    }

    {
        size_t n = 0;
        printf("p_flags=");

        if (ph->p_flags & PF_X)
        {
            if (n++)
                printf("|");
            printf("PF_X");
        }
        if (ph->p_flags & PF_W)
        {
            if (n++)
                printf("|");
            printf("PF_W");
        }
        if (ph->p_flags & PF_R)
        {
            if (n++)
                printf("|");
            printf("PF_R");
        }
        if (ph->p_flags & PF_MASKOS)
        {
            if (n++)
                printf("|");
            printf("PF_MASKOS");
        }
        if (ph->p_flags & PF_MASKPROC)
        {
            if (n++)
                printf("|");
            printf("PF_MASKPROC");
        }
        printf("\n");
    }

    printf("p_offset=%llu %llx\n", OE_LLU(ph->p_offset), OE_LLX(ph->p_offset));
    printf("p_vaddr=%llu %llx\n", OE_LLU(ph->p_vaddr), OE_LLU(ph->p_vaddr));
    printf("p_paddr=%llu\n", OE_LLU(ph->p_paddr));
    printf("p_filesz=%llu\n", OE_LLU(ph->p_filesz));
    printf("p_memsz=%llu\n", OE_LLU(ph->p_memsz));
    printf("p_align=%llu\n", OE_LLU(ph->p_align));
    printf("\n");
}

void Elf64_DumpSymbol(const Elf64* elf, const Elf64_Sym* sym)
{
    unsigned char stb;
    unsigned char stt;
    const char* name;
    const char* secname;

    if (!_Ok(elf) || !sym)
        return;

    stb = (sym->st_info & 0xF0) >> 4;
    stt = (sym->st_info & 0x0F);

    printf("=== Elf64_Sym:\n");

    name = Elf64_GetStringFromStrtab(elf, sym->st_name);

    printf("st_name(%u)=%s\n", sym->st_name, name);

    printf("st_info(bind)=");
    switch (stb)
    {
        case STB_LOCAL:
            printf("STB_LOCAL\n");
            break;
        case STB_GLOBAL:
            printf("STB_GLOBAL\n");
            break;
        case STB_WEAK:
            printf("STB_WEAK\n");
            break;
        case STB_LOOS:
            printf("STB_LOOS\n");
            break;
        case STB_HIOS:
            printf("STB_HIOS\n");
            break;
        case STB_LOPROC:
            printf("STB_LOPROC\n");
            break;
        case STB_HIPROC:
            printf("STB_HIPROC\n");
            break;
        default:
            printf("UNKNOWN\n");
            break;
    }

    printf("st_info(type)=");
    switch (stt)
    {
        case STT_NOTYPE:
            printf("STT_NOTYPE\n");
            break;
        case STT_OBJECT:
            printf("STT_OBJECT\n");
            break;
        case STT_FUNC:
            printf("STT_FUNC\n");
            break;
        case STT_SECTION:
            printf("STT_SECTION\n");
            break;
        case STT_LOOS:
            printf("STT_LOOS\n");
            break;
        case STT_HIOS:
            printf("STT_HIOS\n");
            break;
        case STT_LOPROC:
            printf("STT_LOPROC\n");
            break;
        case STT_HIPROC:
            printf("STT_HIPROC\n");
            break;
        default:
            printf("UNKNOWN\n");
            break;
    }

    if (sym->st_shndx < _GetHeader(elf)->e_shnum)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, sym->st_shndx);
        secname = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
    }

    printf("st_shndx(%u)=%s\n", sym->st_shndx, secname);

    printf("st_value=%016llx\n", OE_LLX(sym->st_value));
    printf("st_size=%llu\n", OE_LLU(sym->st_size));
    printf("\n");
}

int Elf64_VisitSymbols(
    const Elf64* elf,
    int (*visit)(const Elf64_Sym* sym, void* data),
    void* data)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
#if 0
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;
#else
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;
#endif

    if (!_Ok(elf) || !visit)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = _GetShdr(elf, index)))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)_GetSection(elf, index)))
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    /* Dump all the symbol table entries */
    for (i = 1; i < n; i++)
    {
        if (visit(&symtab[i], data) != 0)
        {
            rc = -1;
            goto done;
        }
    }

    rc = 0;

done:
    return rc;
}

static int _DumpSymbol(const Elf64_Sym* sym, void* data)
{
    Elf64_DumpSymbol((Elf64*)data, sym);
    return 0;
}

int Elf64_DumpSymbols(const Elf64* elf)
{
    return Elf64_VisitSymbols(elf, _DumpSymbol, (void*)elf);
}

void Elf64_Dump(const Elf64* elf)
{
    if (!_Ok(elf))
        return;

    Elf64_DumpHeader(_GetHeader(elf));

    for (size_t i = 0; i < _GetHeader(elf)->e_shnum; i++)
        Elf64_DumpShdr(_GetShdr(elf, i), i);

    for (size_t i = 0; i < _GetHeader(elf)->e_phnum; i++)
        _DumpPhdr(_GetPhdr(elf, i), i);
}

static size_t _FindSection(const Elf64* elf, const char* name)
{
    size_t i;

    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
            return i;
    }

    return (size_t)-1;
}

int Elf64_FindSection(
    const Elf64* elf,
    const char* name,
    uint8_t** data,
    size_t* size)
{
    size_t i;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Reject invalid parameters */
    if (!_Ok(elf) || !name || !data || !size)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *data = _GetSection(elf, i);
            *size = sh->sh_size;
            return 0;
        }
    }

    /* Not found! */
    return -1;
}

int Elf64_FindSectionHeader(
    const Elf64* elf,
    const char* name,
    Elf64_Shdr* shdr)
{
    size_t i;

    if (shdr)
        memset(shdr, 0, sizeof(Elf64_Shdr));

    /* Reject invalid parameters */
    if (!_Ok(elf) || !name || !shdr)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *shdr = *_GetShdr(elf, i);
            return 0;
        }
    }

    /* Not found! */
    return -1;
}

void Elf64_DumpSectionNames(const Elf64* elf)
{
    if (!_Ok(elf))
        return;

    size_t index = _GetHeader(elf)->e_shstrndx;
    const Elf64_Shdr* sh = _GetShdr(elf, index);
    const char* start = (const char*)_GetSection(elf, index);
    const char* p = start;
    const char* end = start + sh->sh_size;
    size_t count = 0;

    printf("=== Section names: { ");

    for (p = start; p != end; p += strlen(p) + 1)
    {
        if (count)
            printf(", ");

        printf("\"%s\"", p);

        count++;
    }

    printf(" }\n\n");
}

void Elf64_DumpStrings(const Elf64* elf)
{
    if (!_Ok(elf))
        return;

    /* Find the index of the ".strtab" seciton */
    size_t index;

    if ((index = _FindSection(elf, ".strtab")) == (size_t)-1)
        return;

    {
        const Elf64_Shdr* sh = _GetShdr(elf, index);
        const char* start = (const char*)_GetSection(elf, index);
        const char* p = start;
        const char* end = start + sh->sh_size;
        size_t count = 0;

        printf("=== Strings: { ");

        for (p = start; p != end; p += strlen(p) + 1)
        {
            if (count)
                printf(", ");

            printf("\"%s\"", p);

            count++;
        }

        printf(" }\n\n");
    }
}

static int _IsValidSectionName(const char* s)
{
    if (!s)
        return 0;

    if (*s++ != '.')
        return 0;

    if (!isalpha(*s++))
        return 0;

    while (isalnum(*s) || *s == '_' || *s == '.' || *s == '-')
        s++;

    return *s == '\0';
}

/*
**==============================================================================
**
** Elf64_AddSection()
**
**     Before:
**
**         +------------------+
**         | ELF-64 header    |
**         +------------------+
**         | program headers  |
**         +------------------+
**         | program segments |
**         +------------------+
**         | sections         |
**         +------------------+ <--- insert new section here (SECOFFSET)
**         | .shsttab section |
**         +------------------+ <--- insert new section name here (NAMEOFFSET)
**         | sections         |
**         +------------------+
**         | section headers  |
**         +------------------+ <--- insert new section header here (SHDROFFSET)
**
**     After:
**
**         +------------------+
**         | ELF-64 header    |
**         +------------------+
**         | program headers  |
**         +------------------+
**         | program segments |
**         +------------------+
**         | sections         |
**         +------------------+
**         | new section      | <--- new
**         +------------------+
**         | .shsttab section |
**         | new section name | <--- new
**         +------------------+
**         | sections         |
**         +------------------+
**         | section headers  |
**         +------------------+
**         | new section hdr  | <--- new
**         +------------------+
**
**     Notes:
**         - New section is inserted right before .shsttab section
**         - Add new section just before .shsttab section
**         - Add new section header at end of section headers
**
**==============================================================================
*/

int Elf64_AddSection(
    Elf64* elf,
    const char* name,
    unsigned int type,
    const void* secdata,
    size_t secsize)
{
    int rc = -1;
    size_t shstrndx;
    mem_t mem;
    Elf64_Shdr sh;

    /* Reject invalid parameters */
    if (!_Ok(elf) || !name || !secdata || !secsize)
        GOTO(done);

    /* Fail if new section mame is invalid */
    if (!_IsValidSectionName(name))
        GOTO(done);

    /* Fail if a section with this name already exits */
    if (_FindSection(elf, name) != (size_t)-1)
        GOTO(done);

    /* Save index of section header string table */
    shstrndx = _GetHeader(elf)->e_shstrndx;

    /* Partially initialize the section header (initialize sh.sh_name later) */
    {
        memset(&sh, 0, sizeof(Elf64_Shdr));
        sh.sh_type = type;
        sh.sh_size = secsize;
        sh.sh_addralign = 1;

        /* New section follows .shstrtab section */
        sh.sh_offset = _GetShdr(elf, shstrndx)->sh_offset;
    }

    /* Initialize the memory buffer */
    if (mem_dynamic(&mem, elf->data, elf->size, elf->size) != 0)
        GOTO(done);

    /* Insert new section at SECOFFSET */
    {
        /* Insert the new section */
        if (mem_insert(&mem, sh.sh_offset, secdata, secsize) != 0)
            GOTO(done);

        /* Reset ELF object based on updated memory */
        if (_ResetBuffer(elf, &mem, sh.sh_offset, secsize) != 0)
            GOTO(done);
    }

    /* Insert new section name at NAMEOFFSET */
    {
        /* Calculate insertion offset of the new section name */
        size_t nameoffset = _GetShdr(elf, shstrndx)->sh_offset +
                            _GetShdr(elf, shstrndx)->sh_size;

        /* Calculate number of bytes to be inserted */
        size_t namesize =
            OE_RoundUpToMultiple(strlen(name) + 1, sizeof(Elf64_Shdr));

        /* Insert space for the new name */
        if (mem_insert(&mem, nameoffset, NULL, namesize) != 0)
            GOTO(done);

        /* Copy the section name to the .shstrtab section */
        OE_Strlcat((char*)elf->data + nameoffset, name, namesize);

        /* Reset ELF object based on updated memory */
        if (_ResetBuffer(elf, &mem, nameoffset, namesize) != 0)
            GOTO(done);

        /* Initialize the section name */
        {
            sh.sh_name = (Elf64_Word)_GetShdr(elf, shstrndx)->sh_size;

            /* Check for integer overflow */
            if ((Elf64_Xword)sh.sh_name != _GetShdr(elf, shstrndx)->sh_size)
                GOTO(done);
        }

        /* Update the size of the .shstrtab section */
        _GetShdr(elf, shstrndx)->sh_size += namesize;
    }

    /* Append a new section header at SHDROFFSET */
    {
        /* Verify that shstrndx is within range (shdrs has grown by 1) */
        if (shstrndx > _GetHeader(elf)->e_shnum)
            GOTO(done);

        if (strcmp(Elf64_GetStringFromShstrtab(elf, sh.sh_name), name) != 0)
            GOTO(done);

        /* Insert new section header at end of data */
        if (mem_append(&mem, &sh, sizeof(Elf64_Shdr)) != 0)
            GOTO(done);

        /* Update number of sections */
        _GetHeader(elf)->e_shnum++;

        /* Reset ELF object based on updated memory */
        if (_ResetBuffer(elf, &mem, 0, 0) != 0)
            GOTO(done);
    }

    /* Verify that the section is exactly as expected */
    if (memcmp(
            _GetSection(elf, _GetHeader(elf)->e_shnum - 1), secdata, secsize) !=
        0)
        GOTO(done);

    /* Finally verify that a section with this name exists and matches */
    {
        uint8_t* data;
        size_t size;

        if (Elf64_FindSection(elf, name, &data, &size) != 0)
            GOTO(done);

        if (size != secsize)
            GOTO(done);

        if (memcmp(data, secdata, size) != 0)
            GOTO(done);
    }

    rc = 0;

done:
    return rc;
}

/*
**==============================================================================
**
** Elf64_RemoveSection()
**
**     This function removes a section from the ELF image, which makes three
**     changes:
**
**         - Removes the section itself
**         - Removes the section name (from the .shsttab section)
**         - Removes the section header
**
**==============================================================================
*/

int Elf64_RemoveSection(Elf64* elf, const char* name)
{
    int rc = -1;
    size_t secIndex;
    Elf64_Shdr shdr;

    /* Reject invalid parameters */
    if (!_Ok(elf) || !name)
        goto done;

    /* Find index of this section */
    if ((secIndex = _FindSection(elf, name)) == (size_t)-1)
        goto done;

    /* Save section header */
    shdr = *_GetShdr(elf, secIndex);

    /* Remove the section from the image */
    {
        /* Calculate address of this section */
        uint8_t* first = (uint8_t*)elf->data + shdr.sh_offset;

        /* Calculate end address of this section */
        const uint8_t* last = first + shdr.sh_size;

        /* Calculate address of end of data */
        const uint8_t* end = (const uint8_t*)elf->data + elf->size;

        /* Remove section from the memory image */
        memmove(first, last, end - last);

        /* Adjust the size of the memory image */
        elf->size -= shdr.sh_size;

        /* Update affected section-related offsets */
        {
            ssize_t adjustment;

            /* Check for conversion error */
            if ((adjustment = (ssize_t)shdr.sh_size) < 0)
                goto done;

            _AdjustSectionHeaderOffsets(elf, shdr.sh_offset, -adjustment);
        }
    }

    /* Remove section name from .shsttab without changing the section size */
    {
        /* Get index of .shsttab section header */
        size_t index = _GetHeader(elf)->e_shstrndx;

        /* Calculate address of string */
        char* str = (char*)_GetSection(elf, index) + shdr.sh_name;

        /* Verify that section name matches */
        if (strcmp(str, name) != 0)
            goto done;

        /* Clear the string */
        memset(str, 0, strlen(str));
    }

    /* Remove the section header */
    {
        /* Calculate start-address of section header */
        Elf64_Shdr* first = _GetShdr(elf, secIndex);

        /* Calculate end-address of section header */
        const Elf64_Shdr* last = first + 1;

        /* Calculate end-address of section headers array */
        const Elf64_Shdr* end = first + _GetHeader(elf)->e_shnum;

        /* Remove the header */
        memmove(first, last, (end - last) * sizeof(Elf64_Shdr));

        /* Adjust the number of headers */
        _GetHeader(elf)->e_shnum--;

        /* Adjust the image size */
        elf->size -= sizeof(sizeof(Elf64_Shdr));
    }

    rc = 0;

done:
    return rc;
}

int Elf64_LoadRelocations(const Elf64* elf, void** dataOut, size_t* sizeOut)
{
    int rc = -1;
    uint8_t* data;
    size_t size;
    const Elf64_Rela* p;
    const Elf64_Rela* end;

    if (dataOut)
        *dataOut = 0;

    if (sizeOut)
        *sizeOut = 0;

    if (!_Ok(elf) || !dataOut || !sizeOut)
        goto done;

    /* Find relocation section */
    if (Elf64_FindSection(elf, ".rela.dyn", &data, &size) != 0)
    {
        *dataOut = NULL;
        *sizeOut = 0;
        rc = 0;
        goto done;
    }

    /* Set pointers to start and end of relocation table */
    p = (Elf64_Rela*)data;
    end = (Elf64_Rela*)data + (size / sizeof(Elf64_Rela));

    /* Reject unsupported relocation types */
    for (; p != end; p++)
    {
        if (ELF64_R_TYPE(p->r_info) != R_X86_64_RELATIVE)
        {
            /* Should these really be skipped? */
            continue;
        }
    }

    /* Make a copy of the relocation section (zero-padded to page size) */
    {
        *sizeOut = __OE_RoundUpToPageSize(size);

        if (!(*dataOut = malloc(*sizeOut)))
        {
            *sizeOut = 0;
            goto done;
        }

        memset(*dataOut, 0, *sizeOut);
        memcpy(*dataOut, data, size);
    }

    rc = 0;

done:
    return rc;
}
