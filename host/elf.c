#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openenclave/bits/utils.h>
#include <openenclave/bits/load.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/mem.h>
#include "strings.h"
#include "fopen.h"

#define GOTO(LABEL) \
    do \
    { \
        fprintf(stderr, "GOTO: %s(%u)\n", __FILE__, __LINE__); \
        goto LABEL; \
    } \
    while (0)

int Elf64_TestHeader(
    const Elf64_Ehdr* ehdr)
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

static int _GetHeader(
    Elf64* elf)
{
    int rc = -1;

    if (!elf)
        GOTO(done);

    if (elf->size < sizeof(Elf64_Ehdr))
        GOTO(done);

    /* Set the ELF-64 header */
    elf->ehdr = (Elf64_Ehdr*)elf->data;

    /* Test for a valid ELF-64 ehdr */
    if (Elf64_TestHeader(elf->ehdr) != 0)
        GOTO(done);

    rc = 0;

done:
    return rc;
}

static void _SetShdrs(
    Elf64* elf)
{
    elf->shdrs = (Elf64_Shdr*)(
        (const unsigned char*)elf->data + elf->ehdr->e_shoff);
}

static void _SetPhdrs(
    Elf64* elf)
{
    elf->phdrs = (Elf64_Phdr*)(
        (const unsigned char*)elf->data + elf->ehdr->e_phoff);
}

static int _GetSections(
    Elf64* elf)
{
    int rc = -1;
    size_t i;
    void** data = NULL;

    /* Allocate array of pointers to sections */
    if (!(data = (void**)malloc(elf->ehdr->e_shnum * sizeof(void*))))
        GOTO(done);

    /* Set a pointer to each section */
    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];

        if (sh->sh_type == SHT_NULL)
            data[i] = NULL;
        else
            data[i] = (unsigned char*)elf->data + sh->sh_offset;
    }

    elf->sections = data;

    rc = 0;

done:

    return rc;
}

static int _GetSegments(
    Elf64* elf)
{
    int rc = -1;
    size_t i;
    void** data = NULL;

    /* Allocate array of pointers to segments */
    if (!(data = (void**)malloc(elf->ehdr->e_phnum * sizeof(void*))))
        GOTO(done);

    /* Set pointers to segments */
    for (i = 0; i < elf->ehdr->e_phnum; i++)
    {
        const Elf64_Phdr* ph = &elf->phdrs[i];

        if (ph->p_type == PT_NULL)
            data[i] = NULL;
        else
            data[i] = (unsigned char*)elf->data + ph->p_offset;
    }

    elf->segments = data;

    rc = 0;

done:

    return rc;
}

static int _GetParts(
    Elf64* elf)
{
    int rc = -1;

    if (!elf)
        GOTO(done);

    /* Read ehdr */
    if (_GetHeader(elf) != 0)
        GOTO(done);

    /* Get the section table */
    _SetShdrs(elf);

    /* Allocate and initialize the array of poitners to sections */
    if (_GetSections(elf) != 0)
        GOTO(done);

    /* Get the program table */
    _SetPhdrs(elf);

    /* Allocate and initialize the array of poitners to segments */
    if (_GetSegments(elf) != 0)
        GOTO(done);

    rc = 0;

done:
    return rc;
}

static int _RefetchPtrs(
    Elf64* elf)
{
    free(elf->sections);
    free(elf->segments);
    return _GetParts(elf);
}

int Elf64_Load(
    const char* path,
    Elf64* elf)
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

    /* Read all the parts into the [elf->data:elf->size] */
    if (_GetParts(elf) != 0)
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

int Elf64_Unload(
    Elf64* elf)
{
    int rc = -1;

    if (!elf || elf->magic != ELF_MAGIC)
        goto done;

    if (elf->sections)
        free((void*)elf->sections);

    if (elf->segments)
        free((void*)elf->segments);

    free(elf->data);

    rc = 0;

done:

    return rc;
}

static size_t _FindShdr(
    const Elf64* elf,
    const char* name)
{
    size_t result = (size_t)-1;
    size_t i;

    if (!elf || !name)
        goto done;

    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];
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

const char* Elf64_GetStringFromStrtab(
    const Elf64* elf,
    Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!elf)
        goto done;

    if ((index = _FindShdr(elf, ".strtab")) == (size_t)-1)
        goto done;

    if (index > elf->ehdr->e_shnum)
        goto done;

    sh = &elf->shdrs[index];

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)elf->sections[index] + offset;

done:
    return result;
}

const char* Elf64_GetStringFromShstrtab(
    const Elf64* elf,
    Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!elf)
        goto done;

    index = elf->ehdr->e_shstrndx;

    if (index > elf->ehdr->e_shnum)
        goto done;

    sh = &elf->shdrs[index];

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)elf->sections[index] + offset;

done:
    return result;
}

int Elf64_FindSymbolByName(
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
#if 1
    const char* SECTIONNAME = ".symtab";
    const Elf64_Word SH_TYPE = SHT_SYMTAB;
#else
    const char* SECTIONNAME = ".dynsym";
    const Elf64_Word SH_TYPE = SHT_DYNSYM;
#endif

    if (!elf || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = &elf->shdrs[index]))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)elf->sections[index]))
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

const char* Elf64_GetStringFromDynstr(
    const Elf64* elf,
    Elf64_Word offset)
{
    const char* result = NULL;
    const Elf64_Shdr* sh;
    size_t index;

    if (!elf)
        goto done;

    if ((index = _FindShdr(elf, ".dynstr")) == (size_t)-1)
        goto done;

    if (index > elf->ehdr->e_shnum)
        goto done;

    sh = &elf->shdrs[index];

    if (offset >= sh->sh_size)
        goto done;

    result = (const char*)elf->sections[index] + offset;

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

    if (!elf || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = &elf->shdrs[index]))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)elf->sections[index]))
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

    if (!elf || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = &elf->shdrs[index]))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)elf->sections[index]))
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

    if (!elf || !sym)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = &elf->shdrs[index]))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)elf->sections[index]))
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

void Elf64_DumpHeader(
    const Elf64_Ehdr* h)
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
    printf("e_entry=%llx\n", h->e_entry);
    printf("e_phoff=%llu\n", h->e_phoff);
    printf("e_shoff=%llu\n", h->e_shoff);
    printf("e_flags=%u\n", h->e_flags);
    printf("e_ehsize=%u\n", h->e_ehsize);
    printf("e_phentsize=%u\n", h->e_phentsize);
    printf("e_phnum=%u\n", h->e_phnum);
    printf("e_shentsize=%u\n", h->e_shentsize);
    printf("e_shnum=%u\n", h->e_shnum);
    printf("e_shstrndx=%u\n", h->e_shstrndx);
    printf("\n");
}

void Elf64_DumpShdr(
    const Elf64_Shdr* sh,
    size_t index)
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

    printf("sh_addr=%llu\n", sh->sh_addr);
    printf("sh_offset=%llu\n", sh->sh_offset);
    printf("sh_size=%llu\n", sh->sh_size);
    printf("sh_link=%u\n", sh->sh_link);
    printf("sh_info=%u\n", sh->sh_info);
    printf("sh_addralign=%llu\n", sh->sh_addralign);
    printf("sh_entsize=%llu\n", sh->sh_entsize);
    printf("\n");
}

static size_t _FindSegmentFor(
    const Elf64* elf,
    const Elf64_Shdr* sh)
{
    size_t i = 0; 

    for (i = 0; i < elf->ehdr->e_phnum; i++)
    {
        const Elf64_Phdr* ph = &elf->phdrs[i];

        if (sh->sh_offset >= ph->p_offset && sh->sh_size <= ph->p_memsz)
            return i;
    }

    return (size_t)-1;
}

int Elf64_DumpSections(
    const Elf64* elf)
{
    int rc = -1;
    size_t i;

    if (!elf)
        goto done;

    if (Elf64_TestHeader(elf->ehdr) != 0)
        goto done;

    if (!elf->shdrs)
        goto done;

    if (!elf->sections)
        goto done;

    puts(
    "Num   Name                     Offset           Size             Seg ");
    puts(
    "======================================================================");

    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];
        const char* name = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
        size_t segment = _FindSegmentFor(elf, sh);

        printf("[%03zu] %-24s %016llx %016llx ",
            i, 
            name,
            sh->sh_offset,
            sh->sh_size);

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

static void _DumpPhdr(
    const Elf64_Phdr* ph,
    size_t index)
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

    printf("p_offset=%llu %016llx\n", ph->p_offset, ph->p_offset);
    printf("p_vaddr=%llu %016llx\n", ph->p_vaddr, ph->p_vaddr);
    printf("p_paddr=%llu\n", ph->p_paddr);
    printf("p_filesz=%llu\n", ph->p_filesz);
    printf("p_memsz=%llu\n", ph->p_memsz);
    printf("p_align=%llu\n", ph->p_align);
    printf("\n");
}

void Elf64_DumpSymbol(
    const Elf64* elf,
    const Elf64_Sym* sym)
{
    unsigned char stb;
    unsigned char stt;
    const char* name;
    const char* secname;

    if (!sym)
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

    if (sym->st_shndx < elf->ehdr->e_shnum)
    {
        const Elf64_Shdr* sh = &elf->shdrs[sym->st_shndx];
        secname = Elf64_GetStringFromShstrtab(elf, sh->sh_name);
    }

    printf("st_shndx(%u)=%s\n", sym->st_shndx, secname);

    printf("st_value=%016llx\n", sym->st_value);
    printf("st_size=%llu\n", sym->st_size);
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

    if (!elf)
        goto done;

    /* Find the symbol table section header */
    if ((index = _FindShdr(elf, SECTIONNAME)) == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    if (!(sh = &elf->shdrs[index]))
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(Elf64_Sym))
        goto done;

    /* Set pointer to symbol table section */
    if (!(symtab = (const Elf64_Sym*)elf->sections[index]))
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

int Elf64_DumpSymbols(
    const Elf64* elf)
{
    return Elf64_VisitSymbols(elf, _DumpSymbol, (void*)elf);
}

void Elf64_Dump(
    const Elf64* elf)
{
    if (!elf)
        return;

    Elf64_DumpHeader(elf->ehdr);

    if (elf->shdrs)
    {
        for (size_t i = 0; i < elf->ehdr->e_shnum; i++)
            Elf64_DumpShdr(&elf->shdrs[i], i);
    }

    if (elf->phdrs)
    {
        for (size_t i = 0; i < elf->ehdr->e_phnum; i++)
            _DumpPhdr(&elf->phdrs[i], i);
    }
}

static size_t _FindSection(
    const Elf64* elf,
    const char* name)
{
    size_t i;

    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
            return i;
    }

    return (size_t)-1;
}

int Elf64_FindSection(
    const Elf64* elf,
    const char* name,
    const void** data,
    size_t* size)
{
    size_t i;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Reject invalid parameters */
    if (!elf || !name || !data || !size)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *data = elf->sections[i];
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
    if (!elf || !name || !shdr)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        const Elf64_Shdr* sh = &elf->shdrs[i];
        const char* s = Elf64_GetStringFromShstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *shdr = elf->shdrs[i];
            return 0;
        }
    }

    /* Not found! */
    return -1;
}

void Elf64_DumpSectionNames(
    const Elf64* elf)
{
    size_t index = elf->ehdr->e_shstrndx;
    const Elf64_Shdr* sh = &elf->shdrs[index];
    const char* start = (const char*)elf->sections[index];
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

void Elf64_DumpStrings(
    const Elf64* elf)
{
    /* Find the index of the ".strtab" seciton */
    size_t index;
    
    if ((index = _FindSection(elf, ".strtab")) == (size_t)-1)
        return;

    {
        const Elf64_Shdr* sh = &elf->shdrs[index];
        const char* start = (const char*)elf->sections[index];
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

static void _AdjustSectionOffsets(
    Elf64* elf,
    size_t offset,
    size_t adjustment)
{
    size_t i;

    /* Add ADJUSTMENT to all section offsets greater than OFFSET */

    if (elf->ehdr->e_shoff >= offset)
        elf->ehdr->e_shoff += adjustment;

    for (i = 0; i < elf->ehdr->e_shnum; i++)
    {
        Elf64_Shdr* sh = (Elf64_Shdr*)&elf->shdrs[i];

        if (sh->sh_offset >= offset)
            sh->sh_offset += adjustment;
    }
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
    size_t secoffset;
    size_t nameoffset;
    size_t namesize;
    size_t shstrndx;
    size_t extrasize;
    mem_t mem;

    /* Reject invalid parameters */
    if (!elf || !name || !secdata || !secsize)
        goto done;

    /* Fail if new section mame is invalid */
    if (!_IsValidSectionName(name))
        goto done;

    /* Fail if a section with this name already exits */
    if (_FindSection(elf, name) != (size_t)-1)
        goto done;

    /* Save index of section header string table */
    shstrndx = elf->ehdr->e_shstrndx;

    /* Calculate SECOFFSET (insertion offset of the new section) */
    secoffset = elf->shdrs[shstrndx].sh_offset;

    /* Calculate NAMEOFFSET (insertion offset of the new section name) */
    nameoffset = elf->shdrs[shstrndx].sh_offset + elf->shdrs[shstrndx].sh_size;

    /* Calculate NAMESIZE (bytes to be inserted at NAMEOFFSET */
    namesize = OE_RoundUpToMultiple(strlen(name) + 1, sizeof(Elf64_Shdr));

    /* Set EXTRASIZE to the extra bytes needed to insert these pieces */
    extrasize = secsize + namesize + sizeof(Elf64_Shdr);

    /* Initialize the dynamic memory object */
    if (mem_dynamic(&mem, elf->data, elf->size, elf->size) != 0)
        goto done;

    /* Reserve memory for the extra bytes */
    if (mem_reserve(&mem, elf->size + extrasize) != 0)
        goto done;

    /* Reset data pointer */
    elf->data = mem_mutable_ptr(&mem);

    /* Refetch the pointers in the Elf64 structure */
    if (_RefetchPtrs(elf) != 0)
        goto done;

    /* Insert new section into [SECOFFSET:SECSIZE] */
    {
        /* Update section-related offsets greater than SECOFFSET */
        _AdjustSectionOffsets(elf, secoffset, secsize);

        /* Insert the new section */
        if (mem_insert(&mem, secoffset, secdata, secsize) != 0)
            goto done;

        /* Reset data pointer and size */
        elf->data = mem_mutable_ptr(&mem);
        elf->size = mem_size(&mem);

        /* Refetch the pointers in the Elf64 structure */
        if (_RefetchPtrs(elf) != 0)
            goto done;
    }

    /* Adjust offsets that have shifted (due to above insertion) */
    nameoffset += secsize;
    namesize += secsize;

    /* Insert new section name into [NAMEOFFSET:NAMESIZE] */
    {
        /* Update section-related offsets greater than NAMEOFFSET */
        _AdjustSectionOffsets(elf, nameoffset, namesize);

        /* Insert space for the new name */
        if (mem_insert(&mem, nameoffset, NULL, namesize) != 0)
            goto done;

        /* Reset data pointer and size */
        elf->data = mem_mutable_ptr(&mem);
        elf->size = mem_size(&mem);

        /* Refetch the pointers of the Elf64 structure */
        if (_RefetchPtrs(elf) != 0)
            goto done;

        /* Copy the section name to the .shstrtab section */
        OE_Strlcat((char*)elf->data + nameoffset, name, namesize);

        /* Update the size of the .shstrtab section */
        elf->shdrs[shstrndx].sh_size += strlen(name) + 1;
    }

    /* Append a new section header into [SHDROFFSET:SHDROFFSET] */
    {
        Elf64_Shdr sh;

        /* Initialize the new section header */
        memset(&sh, 0, sizeof(Elf64_Shdr));
        /* ATTN: Bug: Need to assert arithmetic boundary check and downcasting 
         * check
         */
        sh.sh_name = (Elf64_Word)(nameoffset - elf->shdrs[shstrndx].sh_offset);
        sh.sh_type = type;
        sh.sh_offset = secoffset;
        sh.sh_size = secsize;
        sh.sh_addralign = 1;

        /* Verify that the section name lookup works */
        if (strcmp(Elf64_GetStringFromShstrtab(elf, sh.sh_name), name) != 0)
            goto done;

        /* Insert new section header at end of data */
        if (mem_append(&mem, &sh, sizeof(Elf64_Shdr)) != 0)
            goto done;

        /* Reset data pointer and size */
        elf->data = mem_mutable_ptr(&mem);
        elf->size = mem_size(&mem);

        /* Update number of sections */
        elf->ehdr->e_shnum++;

        /* Refetch the pointers to get the new section */
        if (_RefetchPtrs(elf) != 0)
            goto done;
    }

    /* Verify that the section exists */
    if (memcmp(elf->sections[elf->ehdr->e_shnum-1], secdata, secsize) != 0)
        goto done;

    /* Finally verify that a section with this name exists and matches */
    {
        const void* data;
        size_t size;

        if (Elf64_FindSection(elf, name, &data, &size) != 0)
            goto done;

        if (size != secsize)
            goto done;

        if (memcmp(data, secdata, size) != 0)
            goto done;
    }

    rc = 0;

done:
    return rc;
}

int Elf64_LoadRelocations(
    const Elf64* elf,
    void** dataOut,
    size_t* sizeOut)
{
    int rc = -1;
    const void* data;
    size_t size;
    const Elf64_Rela* p;
    const Elf64_Rela* end;

    if (dataOut)
        *dataOut = 0;

    if (sizeOut)
        *sizeOut = 0;

    if (!elf || !dataOut || !sizeOut)
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
