// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <ctype.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "fopen.h"
#include "strings.h"

#define GOTO(LABEL)                                            \
    do                                                         \
    {                                                          \
        fprintf(stderr, "GOTO: %s(%u)\n", __FILE__, __LINE__); \
        goto LABEL;                                            \
    } while (0)

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

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;

    if (ehdr->e_machine != EM_X86_64)
        return -1;

    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr))
        return -1;

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return -1;

    if (ehdr->e_shentsize != sizeof(Elf64_Shdr))
        return -1;

    /* If there is no section header table, then the index should be 0. */
    if (ehdr->e_shnum == 0 && ehdr->e_shstrndx != 0)
        return -1;

    /* If there is a section header table, then the index shouldn't overrun. */
    if (ehdr->e_shnum > 0 && ehdr->e_shstrndx >= ehdr->e_shnum)
        return -1;

    return 0;
}

static bool _IsValidElf64(const Elf64* elf)
{
    if (!elf || elf->size < sizeof(Elf64_Ehdr))
        return false;

    Elf64_Ehdr* header = (Elf64_Ehdr*)elf->data;

    if (Elf64_TestHeader(header) != 0)
        return false;

    /* Ensure that multiplying header size and num entries won't overflow. */
    static_assert(
        sizeof(uint64_t) >=
            sizeof(header->e_phentsize) + sizeof(header->e_phnum),
        "e_phentsize or e_phnum is too large");

    static_assert(
        sizeof(uint64_t) >=
            sizeof(header->e_shentsize) + sizeof(header->e_shnum),
        "e_shentsize or e_shnum is too large");

    uint64_t size = (uint64_t)header->e_phentsize * header->e_phnum;
    uint64_t end;

    /* Check that offsets don't overflow. */
    if (oe_safe_add_u64(header->e_phoff, size, &end) != OE_OK)
        return false;

    if (elf->size < end)
        return false;

    size = (uint64_t)header->e_shentsize * header->e_shnum;
    if (oe_safe_add_u64(header->e_shoff, size, &end) != OE_OK)
        return false;

    if (elf->size < end)
        return false;

    return true;
}

static Elf64_Ehdr* _GetHeader(const Elf64* elf)
{
    return (Elf64_Ehdr*)elf->data;
}

static Elf64_Shdr* _GetShdr(const Elf64* elf, size_t index)
{
    Elf64_Ehdr* header = _GetHeader(elf);

    Elf64_Shdr* shdr_start =
        (Elf64_Shdr*)((uint8_t*)elf->data + header->e_shoff);

    if (index >= header->e_shnum)
        return NULL;

    Elf64_Shdr* shdr = &shdr_start[index];

    /* Check section header segment is within the elf executable.
     * There are no bounds checking for `SHT_NULL` and `SHT_NOBITS`,
     * because they don't have meaningful offset or size values. */
    if (shdr->sh_type == SHT_NULL || shdr->sh_type == SHT_NOBITS)
        return shdr;

    uint64_t end;
    if (oe_safe_add_u64(shdr->sh_offset, shdr->sh_size, &end) != OE_OK)
        return NULL;

    return (end <= elf->size) ? shdr : NULL;
}

static Elf64_Phdr* _GetPhdr(const Elf64* elf, size_t index)
{
    Elf64_Ehdr* header = _GetHeader(elf);

    Elf64_Phdr* phdr_start =
        (Elf64_Phdr*)((uint8_t*)elf->data + header->e_phoff);

    if (index >= header->e_phnum)
        return NULL;

    Elf64_Phdr* phdr = &phdr_start[index];

    /* Check program header segment section is within the elf executable.
     * There are no bounds checks for `PT_NULL`, because it doesn't have
     * a meaningful offset or size value. */
    if (phdr->p_type == PT_NULL)
        return phdr;

    uint64_t end;
    if (oe_safe_add_u64(phdr->p_offset, phdr->p_filesz, &end) != OE_OK)
        return NULL;

    return (end <= elf->size) ? phdr : NULL;
}

static void* _GetSection(const Elf64* elf, size_t index)
{
    const Elf64_Shdr* sh = _GetShdr(elf, index);
    if (sh == NULL)
        return NULL;

    return (sh->sh_type == SHT_NULL || sh->sh_type == SHT_NOBITS)
               ? NULL
               : (uint8_t*)elf->data + sh->sh_offset;
}

static void* _GetSegment(const Elf64* elf, size_t index)
{
    const Elf64_Phdr* ph = _GetPhdr(elf, index);
    if (ph == NULL)
        return NULL;

    return ph->p_type == PT_NULL ? NULL : (uint8_t*)elf->data + ph->p_offset;
}

Elf64_Ehdr* Elf64_GetHeader(const Elf64* elf)
{
    if (!_IsValidElf64(elf))
        return NULL;

    return _GetHeader(elf);
}

void* Elf64_GetSegment(const Elf64* elf, size_t index)
{
    if (!_IsValidElf64(elf))
        return NULL;

    return _GetSegment(elf, index);
}

Elf64_Shdr* Elf64_GetSectionHeader(const Elf64* elf, size_t index)
{
    if (!_IsValidElf64(elf))
        return NULL;

    return _GetShdr(elf, index);
}

Elf64_Phdr* Elf64_GetProgramHeader(const Elf64* elf, size_t index)
{
    if (!_IsValidElf64(elf))
        return NULL;

    return _GetPhdr(elf, index);
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
    int fd = -1;
#if defined(_MSC_VER)
    struct __stat64 statbuf;
#else
    struct stat statbuf;
#endif

    if (elf)
        memset(elf, 0, sizeof(Elf64));

    if (!path || !elf)
        goto done;

    /* Open input file */
    if (oe_fopen(&is, path, "rb") != 0)
        goto done;

#if defined(_MSC_VER)
    fd = _fileno(is);
    if (fd == -1 || _fstat64(fd, &statbuf) != 0)
        goto done;

    if (!(statbuf.st_mode & _S_IFREG) != 0)
        goto done;
#else
    fd = fileno(is);
    if (fd == -1 || fstat(fd, &statbuf) != 0)
        goto done;

    /* Reject non-regular files */
    if (!S_ISREG(statbuf.st_mode))
        goto done;
#endif

    /* Store the size of this file */
    elf->size = statbuf.st_size;

    /* Allocate the data to hold this image */
    if (!(elf->data = malloc(elf->size)))
        goto done;

    /* Read the file into memory */
    if (fread(elf->data, 1, elf->size, is) != elf->size)
        goto done;

    /* Validate the ELF file. */
    if (!_IsValidElf64(elf))
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

    if (!_IsValidElf64(elf))
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
        if (sh == NULL)
            goto done;

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

static inline bool _IsValidStringTable(const char* table, size_t size)
{
    /* The ELF spec requires the string table to have the first and last byte
     * equal to 0. Checking if the last byte is 0 also ensures that any pointer
     * within the table will be null terminated, because the table itself is
     * null terminated. */
    return size >= 2 && table[0] == '\0' && table[size - 1] == '\0';
}

static const char* _GetStringFromSectionIndex(
    const Elf64* elf,
    size_t index,
    Elf64_Word offset)
{
    const Elf64_Shdr* sh;
    const char* result = NULL;

    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
        goto done;

    sh = _GetShdr(elf, index);

    if (sh == NULL || offset >= sh->sh_size)
        goto done;

    /* If the section is null, the elf file is corrupted, since only `SHT_NULL`
     * and `SHT_NOBITS` can have nonexistent sections. */
    result = (const char*)_GetSection(elf, index);
    if (result == NULL)
        goto done;

    if (!_IsValidStringTable(result, sh->sh_size))
        goto done;

    result += offset;

done:
    return result;
}

const char* Elf64_GetStringFromStrtab(const Elf64* elf, Elf64_Word offset)
{
    size_t index;

    if (!_IsValidElf64(elf))
        return NULL;

    if ((index = _FindShdr(elf, ".strtab")) == (size_t)-1)
        return NULL;

    return _GetStringFromSectionIndex(elf, index, offset);
}

const char* Elf64_GetStringFromShstrtab(const Elf64* elf, Elf64_Word offset)
{
    size_t index;

    if (!_IsValidElf64(elf))
        return NULL;

    index = _GetHeader(elf)->e_shstrndx;
    return _GetStringFromSectionIndex(elf, index, offset);
}

int Elf64_FindSymbolByName(const Elf64* elf, const char* name, Elf64_Sym* sym)
{
    int rc = -1;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;

    if (!_IsValidElf64(elf) || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
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
    size_t index;

    if (!_IsValidElf64(elf))
        return NULL;

    if ((index = _FindShdr(elf, ".dynstr")) == (size_t)-1)
        return NULL;

    return _GetStringFromSectionIndex(elf, index, offset);
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

    if (!_IsValidElf64(elf) || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
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
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;

    if (!_IsValidElf64(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
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
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;

    if (!_IsValidElf64(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
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
        if (ph == NULL)
            return (size_t)-1;

        if (sh->sh_offset >= ph->p_offset && sh->sh_size <= ph->p_memsz)
            return i;
    }

    return (size_t)-1;
}

int Elf64_DumpSections(const Elf64* elf)
{
    int rc = -1;
    size_t i;

    if (!_IsValidElf64(elf))
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
        if (sh == NULL)
        {
            printf("[%03zu]: Invalid Section.\n", i);
            continue;
        }

        const char* name = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
        if (name == NULL)
        {
            printf("Unknown section for index %03zu\n", i);
            continue;
        }

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

    printf(
        "p_offset=%llu %016llx\n", OE_LLU(ph->p_offset), OE_LLX(ph->p_offset));
    printf("p_vaddr=%llu %016llx\n", OE_LLU(ph->p_vaddr), OE_LLU(ph->p_vaddr));
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
    const char* secname = NULL;

    if (!_IsValidElf64(elf) || !sym)
        return;

    stb = (sym->st_info & 0xF0) >> 4;
    stt = (sym->st_info & 0x0F);

    printf("=== Elf64_Sym:\n");

    name = Elf64_GetStringFromStrtab(elf, sym->st_name);
    if (name == NULL)
    {
        printf("Unknown Symbol\n");
        return;
    }

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
        if (sh != NULL)
            secname = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
    }

    if (secname == NULL)
        secname = "Unknown section name";

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
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;

    if (!_IsValidElf64(elf) || !visit)
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
    if (!_IsValidElf64(elf))
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
        if (sh == NULL)
            return (size_t)-1;

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
    if (!_IsValidElf64(elf) || !name || !data || !size)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        if (sh == NULL)
            return -1;

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
    if (!_IsValidElf64(elf) || !name || !shdr)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _GetHeader(elf)->e_shnum; i++)
    {
        const Elf64_Shdr* sh = _GetShdr(elf, i);
        if (sh == NULL)
            return -1;

        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *shdr = *sh;
            return 0;
        }
    }

    /* Not found! */
    return -1;
}

static void _PrintStringTable(const char* buf, size_t size)
{
    const char* start = buf;
    const char* end = buf + size;
    size_t count = 0;

    printf("{ ");
    for (const char* p = start; p != end; p++)
    {
        if (*p == '\0')
        {
            if (count)
                printf(", ");

            printf("\"%s\"", start);
            start = p + 1;
            count++;
        }
    }

    /* String table was not null terminated. */
    if (start != end)
    {
        if (count)
            printf(", ");

        printf("\"");
        fwrite(start, 1, end - start, stdout);
        printf("\"");
    }
    printf(" }\n");
}

void Elf64_DumpSectionNames(const Elf64* elf)
{
    if (!_IsValidElf64(elf))
        return;

    size_t index = _GetHeader(elf)->e_shstrndx;
    if (index == 0)
    {
        printf("No section name table exists in ELF file.\n");
        return;
    }

    const Elf64_Shdr* sh = _GetShdr(elf, index);
    if (sh == NULL)
    {
        printf("Invalid header for section name table.\n");
        return;
    }

    const char* start = (const char*)_GetSection(elf, index);
    if (start == NULL)
    {
        printf("Count not find section name table.\n");
        return;
    }

    printf("=== Section names: ");
    _PrintStringTable(start, sh->sh_size);
    printf("\n");
}

void Elf64_DumpStrings(const Elf64* elf)
{
    if (!_IsValidElf64(elf))
        return;

    /* Find the index of the ".strtab" section */
    size_t index;

    if ((index = _FindSection(elf, ".strtab")) == (size_t)-1)
        return;

    {
        const Elf64_Shdr* sh = _GetShdr(elf, index);
        if (sh == NULL)
            return;

        const char* start = (const char*)_GetSection(elf, index);
        if (start == NULL)
        {
            printf("Count not find string table.\n");
            return;
        }

        printf("=== Strings: ");
        _PrintStringTable(start, sh->sh_size);
        printf("\n");
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
    if (!_IsValidElf64(elf) || !name || !secdata || !secsize)
        GOTO(done);

    /* Fail if new section name is invalid */
    if (!_IsValidSectionName(name))
        GOTO(done);

    /* Fail if a section with this name already exits */
    if (_FindSection(elf, name) != (size_t)-1)
        GOTO(done);

    /* Save index of section header string table */
    shstrndx = _GetHeader(elf)->e_shstrndx;

    /* For simplicity, error out if there isn't a section string table. */
    if (shstrndx == 0)
        GOTO(done);

    /* Partially initialize the section header (initialize sh.sh_name later) */
    {
        memset(&sh, 0, sizeof(Elf64_Shdr));
        sh.sh_type = type;
        sh.sh_size = secsize;
        sh.sh_addralign = 1;

        /* New section follows .shstrtab section */
        Elf64_Shdr* shdr = _GetShdr(elf, shstrndx);
        if (shdr == NULL)
            GOTO(done);
        sh.sh_offset = shdr->sh_offset;
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
        Elf64_Shdr* shdr = _GetShdr(elf, shstrndx);
        if (shdr == NULL)
            GOTO(done);

        /* Calculate insertion offset of the new section name */
        uint64_t nameoffset = shdr->sh_offset + shdr->sh_size;

        /* Calculate number of bytes to be inserted */
        size_t namesize;
        if (oe_safe_add_sizet(strlen(name), 1, &namesize) != OE_OK)
            GOTO(done);

        namesize = oe_round_up_to_multiple(namesize, sizeof(Elf64_Shdr));

        /* Insert space for the new name */
        if (mem_insert(&mem, nameoffset, NULL, namesize) != 0)
            GOTO(done);

        /* Copy the section name to the .shstrtab section */
        oe_strlcat((char*)elf->data + nameoffset, name, namesize);

        /* Reset ELF object based on updated memory */
        if (_ResetBuffer(elf, &mem, nameoffset, namesize) != 0)
            GOTO(done);

        /* Initialize the section name */
        shdr = _GetShdr(elf, shstrndx);
        {
            sh.sh_name = (Elf64_Word)shdr->sh_size;

            /* Check for integer overflow */
            if ((Elf64_Xword)sh.sh_name != shdr->sh_size)
                GOTO(done);
        }

        /* Update the size of the .shstrtab section */
        static_assert(
            sizeof(namesize) == sizeof(uint64_t),
            "sizeof(namesize) != sizeof(uint64_t)");

        if (oe_safe_add_u64(
                shdr->sh_size, (uint64_t)namesize, &shdr->sh_size) != OE_OK)
            GOTO(done);
    }

    /* Append a new section header at SHDROFFSET */
    {
        /* Verify that shstrndx is within range (shdrs has grown by 1) */
        if (shstrndx > _GetHeader(elf)->e_shnum)
            GOTO(done);

        const char* secname = Elf64_GetStringFromShstrtab(elf, sh.sh_name);
        if (!secname || strcmp(secname, name) != 0)
            GOTO(done);

        /* Insert new section header at end of data */
        if (mem_append(&mem, &sh, sizeof(Elf64_Shdr)) != 0)
            GOTO(done);

        /* Update number of sections */
        Elf64_Ehdr* ehdr = _GetHeader(elf);
        if (oe_safe_add_u16(ehdr->e_shnum, 1, &ehdr->e_shnum) != OE_OK)
            GOTO(done);

        /* Reset ELF object based on updated memory */
        if (_ResetBuffer(elf, &mem, 0, 0) != 0)
            GOTO(done);
    }

    /* Verify that the section is exactly as expected */
    {
        const void* section = _GetSection(elf, _GetHeader(elf)->e_shnum - 1);
        if (section == NULL)
            GOTO(done);

        if (memcmp(section, secdata, secsize) != 0)
            GOTO(done);
    }

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
    Elf64_Shdr* shdr;

    /* Reject invalid parameters */
    if (!_IsValidElf64(elf) || !name)
        goto done;

    /* Find index of this section */
    if ((secIndex = _FindSection(elf, name)) == (size_t)-1)
        goto done;

    /* Save section header */
    shdr = _GetShdr(elf, secIndex);
    if (shdr == NULL)
        goto done;

    /* Remove the section from the image */
    {
        /* Calculate address of this section */
        uint8_t* first = (uint8_t*)elf->data + shdr->sh_offset;

        /* Calculate end address of this section */
        const uint8_t* last = first + shdr->sh_size;

        /* Calculate address of end of data */
        const uint8_t* end = (const uint8_t*)elf->data + elf->size;

        /* Remove section from the memory image */
        memmove(first, last, end - last);

        /* Adjust the size of the memory image */
        elf->size -= shdr->sh_size;

        /* Update affected section-related offsets */
        {
            ssize_t adjustment;

            /* Check for conversion error */
            if ((adjustment = (ssize_t)shdr->sh_size) < 0)
                goto done;

            _AdjustSectionHeaderOffsets(elf, shdr->sh_offset, -adjustment);
        }
    }

    /* Remove section name from .shsttab without changing the section size */
    {
        /* Get index of .shsttab section header */
        size_t index = _GetHeader(elf)->e_shstrndx;
        if (index != 0)
        {
            /* Calculate address of string */
            char* str = (char*)_GetSection(elf, index);
            if (str == NULL)
                goto done;

            /* Sanity Checks. */
            Elf64_Shdr* strshdr = _GetShdr(elf, index);
            if (strshdr == NULL)
                goto done;

            if (!_IsValidStringTable(str, strshdr->sh_size))
                goto done;

            /* Check for overflow. */
            if (shdr->sh_name >= strshdr->sh_size)
                goto done;

            str += shdr->sh_name;

            /* Verify that section name matches */
            if (strcmp(str, name) != 0)
                goto done;

            /* Clear the string */
            memset(str, 0, strlen(str));
        }
    }

    /* Remove the section header */
    {
        /* Calculate start-address of section header */
        Elf64_Shdr* first = _GetShdr(elf, secIndex);
        if (first == NULL)
            goto done;

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
    size_t index;
    Elf64_Shdr* shdr;
    uint8_t* data;
    size_t size;
    const Elf64_Rela* p;
    const Elf64_Rela* end;

    if (dataOut)
        *dataOut = 0;

    if (sizeOut)
        *sizeOut = 0;

    if (!_IsValidElf64(elf) || !dataOut || !sizeOut)
        goto done;

    /* Get Shdr for the ".rela.dyn" section. */
    index = _FindShdr(elf, ".rela.dyn");
    if (index == (size_t)-1)
    {
        *dataOut = NULL;
        *sizeOut = 0;
        rc = 0;
        goto done;
    }

    /* Check invalid indexes. */
    if (index == 0 || index >= _GetHeader(elf)->e_shnum)
        goto done;

    shdr = _GetShdr(elf, index);
    if (shdr == NULL)
        goto done;

    /* Sanity check for the entry size. */
    if (shdr->sh_entsize != sizeof(Elf64_Rela))
        goto done;

    /* Get the relocation section. */
    size = shdr->sh_size;
    data = _GetSection(elf, index);
    if (data == NULL)
        goto done;

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
        *sizeOut = __oe_round_up_to_page_size(size);

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

const char* Elf64_GetFunctionName(const Elf64* elf, Elf64_Addr addr)
{
    const char* ret = NULL;
    size_t index;
    const Elf64_Shdr* sh;
    const Elf64_Sym* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;

    if (!_IsValidElf64(elf))
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

    /* Look for a function symbol that contains the given address */
    for (i = 1; i < n; i++)
    {
        const Elf64_Sym* p = &symtab[i];
        unsigned int stt = (p->st_info & 0x0F);

        /* If this symbol is a function */
        if (stt == STT_FUNC)
        {
            /* If this symbol contains the address */
            uint64_t end;
            if (oe_safe_add_u64(p->st_value, p->st_size, &end) != OE_OK)
                goto done;

            if ((addr >= p->st_value) && (addr <= end))
            {
                ret = Elf64_GetStringFromStrtab(elf, p->st_name);
                goto done;
            }
        }
    }

done:
    return ret;
}
