// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <ctype.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../fopen.h"
#include "../memalign.h"
#include "../strings.h"

#define GOTO(LABEL)                                            \
    do                                                         \
    {                                                          \
        fprintf(stderr, "GOTO: %s(%u)\n", __FILE__, __LINE__); \
        goto LABEL;                                            \
    } while (0)

/* forward declaration to resolve dependencies */
static const char* _get_string_from_shstrtab_internal(
    const void* ptr,
    elf64_word_t offset,
    bool use_header);

int elf64_test_header(const elf64_ehdr_t* ehdr)
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

static bool _is_valid_elf64(const elf64_t* elf)
{
    if (!elf || elf->size < sizeof(elf64_ehdr_t))
        return false;

    elf64_ehdr_t* header = (elf64_ehdr_t*)elf->data;

    if (elf64_test_header(header) != 0)
        return false;

    /* Ensure that multiplying header size and num entries won't overflow. */
    OE_STATIC_ASSERT(
        sizeof(uint64_t) >=
        sizeof(header->e_phentsize) + sizeof(header->e_phnum));

    OE_STATIC_ASSERT(
        sizeof(uint64_t) >=
        sizeof(header->e_shentsize) + sizeof(header->e_shnum));

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

static elf64_ehdr_t* _get_header(const elf64_t* elf)
{
    return (elf64_ehdr_t*)elf->data;
}

static size_t _get_size_from_header(const elf64_ehdr_t* header)
{
    /* calculate the size of elf image based on the formula:
     * offset to the section header + section size * number of sections
     * Note that all the sections have the same size according to the ELF
     * specification. */
    return header->e_shoff + (header->e_shentsize * header->e_shnum);
}

static elf64_shdr_t* _get_shdr_internal(
    const void* ptr,
    size_t index,
    bool use_header)
{
    elf64_ehdr_t* header;
    size_t elf_size = 0;

    if (!use_header)
    {
        const elf64_t* elf = (const elf64_t*)ptr;
        header = _get_header(elf);
        elf_size = elf->size;
    }
    else
    {
        header = (elf64_ehdr_t*)ptr;
        elf_size = _get_size_from_header(header);
    }

    elf64_shdr_t* shdr_start =
        (elf64_shdr_t*)((uint8_t*)header + header->e_shoff);

    if (index >= header->e_shnum)
        return NULL;

    elf64_shdr_t* shdr = &shdr_start[index];

    /* Check section header segment is within the elf executable.
     * There are no bounds checking for `SHT_NULL` and `SHT_NOBITS`,
     * because they don't have meaningful offset or size values. */
    if (shdr->sh_type == SHT_NULL || shdr->sh_type == SHT_NOBITS)
        return shdr;

    uint64_t end;
    if (oe_safe_add_u64(shdr->sh_offset, shdr->sh_size, &end) != OE_OK)
        return NULL;

    return (end <= elf_size) ? shdr : NULL;
}

static elf64_shdr_t* _get_shdr(const elf64_t* elf, size_t index)
{
    return _get_shdr_internal((const void*)elf, index, false /* use_header */);
}

static elf64_phdr_t* _get_phdr(const elf64_t* elf, size_t index)
{
    elf64_ehdr_t* header = _get_header(elf);

    elf64_phdr_t* phdr_start =
        (elf64_phdr_t*)((uint8_t*)elf->data + header->e_phoff);

    if (index >= header->e_phnum)
        return NULL;

    elf64_phdr_t* phdr = &phdr_start[index];

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

static void* _get_section_internal(
    const void* ptr,
    size_t index,
    bool use_header)
{
    const elf64_shdr_t* sh = _get_shdr_internal(ptr, index, use_header);
    if (sh == NULL)
        return NULL;

    const elf64_ehdr_t* header = NULL;

    if (!use_header)
        header = _get_header((const elf64_t*)ptr);
    else
        header = (const elf64_ehdr_t*)ptr;

    return (sh->sh_type == SHT_NULL || sh->sh_type == SHT_NOBITS)
               ? NULL
               : (uint8_t*)header + sh->sh_offset;
}

static void* _get_section(const elf64_t* elf, size_t index)
{
    return _get_section_internal(
        (const void*)elf, index, false /* use_header */);
}

void* elf_get_section(const elf64_t* elf, size_t index)
{
    return _get_section(elf, index);
}

static void* _get_segment(const elf64_t* elf, size_t index)
{
    const elf64_phdr_t* ph = _get_phdr(elf, index);
    if (ph == NULL)
        return NULL;

    return ph->p_type == PT_NULL ? NULL : (uint8_t*)elf->data + ph->p_offset;
}

elf64_ehdr_t* elf64_get_header(const elf64_t* elf)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_header(elf);
}

void* elf64_get_segment(const elf64_t* elf, size_t index)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_segment(elf, index);
}

elf64_shdr_t* elf64_get_section_header(const elf64_t* elf, size_t index)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_shdr(elf, index);
}

elf64_phdr_t* elf64_get_program_header(const elf64_t* elf, size_t index)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_phdr(elf, index);
}

/* Add adjustment value to all section offsets greater than OFFSET */
static void _adjust_section_header_offsets(
    elf64_t* elf,
    size_t offset,
    ssize_t adjustment)
{
    size_t i;
    elf64_ehdr_t* ehdr = _get_header(elf);

    /* Adjust section header offset */
    if (ehdr->e_shoff >= offset)
        ehdr->e_shoff += (uint64_t)adjustment;

    elf64_shdr_t* shdrs = (elf64_shdr_t*)((uint8_t*)elf->data + ehdr->e_shoff);

    /* Adjust offsets to individual headers */
    for (i = 0; i < ehdr->e_shnum; i++)
    {
        elf64_shdr_t* sh = &shdrs[i];

        if (sh->sh_offset >= offset)
            sh->sh_offset += (uint64_t)adjustment;
    }
}

static int _reset_buffer(
    elf64_t* elf,
    mem_t* mem,
    size_t offset,
    ssize_t adjustment)
{
    /* Reset the pointers to the ELF image */
    elf->data = mem_mutable_ptr(mem);
    elf->size = mem_size(mem);

    /* Adjust section header offsets greater than offset */
    _adjust_section_header_offsets(elf, offset, adjustment);

    return 0;
}

int elf64_load(const char* path, elf64_t* elf)
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
        memset(elf, 0, sizeof(elf64_t));

    if (!path || !elf)
        goto done;

    /* Open input file */
    if (oe_fopen(&is, path, "rb") != 0)
        goto done;

#if defined(_MSC_VER)
    fd = _fileno(is);
    if (fd == -1 || _fstat64(fd, &statbuf) != 0)
        goto done;

    if ((statbuf.st_mode & _S_IFREG) == 0)
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
    elf->size = (size_t)statbuf.st_size;

    /* Allocate the data to hold this image */
    elf->data = malloc(elf->size);
    if (!elf->data)
        goto done;

    /* Read the file into memory */
    if (fread(elf->data, 1, elf->size, is) != elf->size)
        goto done;

    /* Validate the ELF file. */
    if (!_is_valid_elf64(elf))
        goto done;

    /* Set the magic number */
    elf->magic = ELF_MAGIC;

    rc = 0;

done:

    if (is)
        fclose(is);

    if (rc != 0 && elf)
    {
        free(elf->data);
        memset(elf, 0, sizeof(elf64_t));
    }

    if (rc)
        OE_TRACE_ERROR("path=%s\n", path);

    return rc;
}

int elf64_unload(elf64_t* elf)
{
    int rc = -1;

    if (!_is_valid_elf64(elf))
        goto done;

    free(elf->data);

    rc = 0;

done:

    return rc;
}

static size_t _find_shdr_internal(
    const void* ptr,
    const char* name,
    bool use_header)
{
    const elf64_ehdr_t* header = NULL;
    const elf64_t* elf = NULL;
    size_t result = (size_t)-1;
    size_t i;

    if (!use_header)
    {
        elf = (const elf64_t*)ptr;
        header = _get_header(elf);
    }
    else
        header = (const elf64_ehdr_t*)ptr;

    for (i = 0; i < header->e_shnum; i++)
    {
        const elf64_shdr_t* sh = _get_shdr_internal(ptr, i, use_header);
        if (sh == NULL)
            goto done;

        const char* s =
            _get_string_from_shstrtab_internal(ptr, sh->sh_name, use_header);
        if (s && strcmp(name, s) == 0)
        {
            result = i;
            goto done;
        }
    }

done:
    return result;
}

static size_t _find_shdr(const elf64_t* elf, const char* name)
{
    return _find_shdr_internal((const void*)elf, name, false /* use_header */);
}

size_t elf_find_shdr(const elf64_t* elf, const char* name)
{
    return _find_shdr(elf, name);
}

static inline bool _is_valid_string_table(const char* table, size_t size)
{
    /* The ELF spec requires the string table to have the first and last byte
     * equal to 0. Checking if the last byte is 0 also ensures that any pointer
     * within the table will be null terminated, because the table itself is
     * null terminated. */
    return size >= 2 && table[0] == '\0' && table[size - 1] == '\0';
}

static const char* _get_string_from_section_by_index_internal(
    const void* ptr,
    size_t index,
    elf64_word_t offset,
    bool use_header)
{
    const elf64_ehdr_t* header = NULL;
    const elf64_shdr_t* sh = NULL;
    const char* result = NULL;

    if (!use_header)
        header = _get_header((const elf64_t*)ptr);
    else
        header = (const elf64_ehdr_t*)ptr;

    if (index == 0 || index >= header->e_shnum)
        goto done;

    sh = _get_shdr_internal(ptr, index, use_header);

    if (sh == NULL || offset >= sh->sh_size)
        goto done;

    /* If the section is null, the elf file is corrupted, since only `SHT_NULL`
     * and `SHT_NOBITS` can have nonexistent sections. */
    result = (const char*)_get_section_internal(ptr, index, use_header);
    if (result == NULL)
        goto done;

    if (!_is_valid_string_table(result, sh->sh_size))
        goto done;

    result += offset;

done:
    return result;
}

static const char* _get_string_from_section_by_index(
    const elf64_t* elf,
    size_t index,
    elf64_word_t offset)
{
    return _get_string_from_section_by_index_internal(
        (const void*)elf, index, offset, false /* use_header */);
}

static const char* _get_string_from_shstrtab_internal(
    const void* ptr,
    elf64_word_t offset,
    bool use_header)
{
    size_t index;

    if (!use_header)
        index = _get_header((const elf64_t*)ptr)->e_shstrndx;
    else
        index = ((const elf64_ehdr_t*)ptr)->e_shstrndx;

    return _get_string_from_section_by_index_internal(
        ptr, index, offset, use_header);
}

const char* elf64_get_string_from_shstrtab(
    const elf64_t* elf,
    elf64_word_t offset)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_string_from_shstrtab_internal(
        (const void*)elf, offset, false /* use_header */);
}

const char* elf64_get_string_from_strtab(
    const elf64_t* elf,
    elf64_word_t offset)
{
    size_t index;

    if (!_is_valid_elf64(elf))
        return NULL;

    index = _find_shdr(elf, ".strtab");
    if (index == (size_t)-1)
        return NULL;

    return _get_string_from_section_by_index(elf, index, offset);
}

int elf64_find_symbol_by_name(
    const elf64_t* elf,
    const char* name,
    elf64_sym_t* sym)
{
    int rc = -1;
    size_t index;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".symtab";
    const elf64_word_t SH_TYPE = SHT_SYMTAB;

    if (!_is_valid_elf64(elf) || !name || !sym)
        goto done;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    if (index == 0 || index >= _get_header(elf)->e_shnum)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!symtab)
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const elf64_sym_t* p = &symtab[i];
        const char* s;

        /* Skip empty names */
        if (p->st_name == 0)
            continue;

        /* If illegal name */
        s = elf64_get_string_from_strtab(elf, p->st_name);
        if (!s)
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

int elf64_get_dynamic_symbol_table(
    const elf64_t* elf,
    const elf64_sym_t** symtab,
    size_t* size)
{
    int rc = -1;
    size_t index;
    const elf64_shdr_t* sh;
    const char* SECTIONNAME = ".dynsym";
    const elf64_word_t SH_TYPE = SHT_DYNSYM;

    if (!_is_valid_elf64(elf) || !symtab || !size)
        goto done;

    *symtab = NULL;
    *size = 0;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    if (index == 0 || index >= _get_header(elf)->e_shnum)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    *symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!*symtab)
        goto done;

    /* Calculate number of symbol table entries */
    *size = sh->sh_size / sh->sh_entsize;

    rc = 0;
done:
    return rc;
}

static const char* _get_string_from_dynstr_internal(
    const void* ptr,
    elf64_word_t offset,
    bool use_header)
{
    size_t index;

    index = _find_shdr_internal(ptr, ".dynstr", use_header);
    if (index == (size_t)-1)
        return NULL;

    return _get_string_from_section_by_index_internal(
        ptr, index, offset, use_header);
}

const char* elf64_get_string_from_dynstr(
    const elf64_t* elf,
    elf64_word_t offset)
{
    if (!_is_valid_elf64(elf))
        return NULL;

    return _get_string_from_dynstr_internal(
        (const void*)elf, offset, false /* use_header */);
}

static int _find_dynamic_symbol_by_name(
    const void* ptr,
    const char* name,
    elf64_sym_t* sym,
    bool use_header)
{
    int rc = -1;
    size_t index;
    const elf64_ehdr_t* header = NULL;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".dynsym";
    const elf64_word_t SH_TYPE = SHT_DYNSYM;

    /* Find the symbol table section header */
    index = _find_shdr_internal(ptr, SECTIONNAME, use_header);
    if (index == (size_t)-1)
        goto done;

    if (!use_header)
        header = _get_header((const elf64_t*)ptr);
    else
        header = (const elf64_ehdr_t*)ptr;

    if (index == 0 || index >= header->e_shnum)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr_internal(ptr, index, use_header);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section_internal(ptr, index, use_header);
    if (!symtab)
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const elf64_sym_t* p = &symtab[i];
        const char* s;

        /* Skip empty names */
        if (p->st_name == 0)
            continue;

        /* If illegal name */
        s = _get_string_from_dynstr_internal(ptr, p->st_name, use_header);
        if (!s)
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

int elf64_find_dynamic_symbol_by_name(
    const elf64_t* elf,
    const char* name,
    elf64_sym_t* sym)
{
    if (!_is_valid_elf64(elf) || !name || !sym)
        return -1;

    return _find_dynamic_symbol_by_name(
        (const void*)elf, name, sym, false /* use_header */);
}

int elf64_find_dynamic_symbol_by_name_with_header(
    const elf64_ehdr_t* header,
    const char* name,
    elf64_sym_t* sym)
{
    if (elf64_test_header(header) != 0 || !name || !sym)
        return -1;

    return _find_dynamic_symbol_by_name(
        (const void*)header, name, sym, true /* use_header */);
}

int elf64_find_symbol_by_address(
    const elf64_t* elf,
    elf64_addr_t addr,
    unsigned int type,
    elf64_sym_t* sym)
{
    int rc = -1;
    size_t index;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".symtab";
    const elf64_word_t SH_TYPE = SHT_SYMTAB;

    if (!_is_valid_elf64(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    if (index == 0 || index >= _get_header(elf)->e_shnum)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!symtab)
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const elf64_sym_t* p = &symtab[i];
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

int elf64_find_dynamic_symbol_by_address(
    const elf64_t* elf,
    elf64_addr_t addr,
    unsigned int type,
    elf64_sym_t* sym)
{
    int rc = -1;
    size_t index;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".dynsym";
    const elf64_word_t SH_TYPE = SHT_DYNSYM;

    if (!_is_valid_elf64(elf) || !sym)
        goto done;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    if (index == 0 || index >= _get_header(elf)->e_shnum)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!symtab)
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    for (i = 1; i < n; i++)
    {
        const elf64_sym_t* p = &symtab[i];
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

void elf64_dump_header(const elf64_ehdr_t* h)
{
    if (!h || elf64_test_header(h) != 0)
        return;

    printf("=== elf64_ehdr_t:\n");

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

void elf64_dump_shdr(const elf64_shdr_t* sh, size_t index)
{
    if (!sh)
        return;

    printf("=== elf64_shdr_t[%03zu]:\n", index);
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

static size_t _find_segment_for(const elf64_t* elf, const elf64_shdr_t* sh)
{
    size_t i = 0;

    for (i = 0; i < _get_header(elf)->e_phnum; i++)
    {
        const elf64_phdr_t* ph = _get_phdr(elf, i);
        if (ph == NULL)
            return (size_t)-1;

        if (sh->sh_offset >= ph->p_offset && sh->sh_size <= ph->p_memsz)
            return i;
    }

    return (size_t)-1;
}

int elf64_dump_sections(const elf64_t* elf)
{
    int rc = -1;
    size_t i;

    if (!_is_valid_elf64(elf))
        goto done;

    if (elf64_test_header(_get_header(elf)) != 0)
        goto done;

    puts("Num   Name                     Offset           Size             "
         "Seg ");
    puts("====================================================================="
         "=");

    for (i = 0; i < _get_header(elf)->e_shnum; i++)
    {
        const elf64_shdr_t* sh = _get_shdr(elf, i);
        if (sh == NULL)
        {
            printf("[%03zu]: Invalid Section.\n", i);
            continue;
        }

        const char* name = elf64_get_string_from_shstrtab(elf, sh->sh_name);
        if (name == NULL)
        {
            printf("Unknown section for index %03zu\n", i);
            continue;
        }

        size_t segment = _find_segment_for(elf, sh);

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

static void _dump_phdr(const elf64_phdr_t* ph, size_t index)
{
    if (!ph)
        return;

    printf("=== elf64_phdr_t[%03zu]:\n", index);

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

void elf64_dump_symbol(const elf64_t* elf, const elf64_sym_t* sym)
{
    unsigned char stb;
    unsigned char stt;
    const char* name;
    const char* secname = NULL;

    if (!_is_valid_elf64(elf) || !sym)
        return;

    stb = (sym->st_info & 0xF0) >> 4;
    stt = (sym->st_info & 0x0F);

    printf("=== elf64_sym_t:\n");

    name = elf64_get_string_from_strtab(elf, sym->st_name);
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

    if (sym->st_shndx < _get_header(elf)->e_shnum)
    {
        const elf64_shdr_t* sh = _get_shdr(elf, sym->st_shndx);
        if (sh != NULL)
            secname = elf64_get_string_from_shstrtab(elf, sh->sh_name);
    }

    if (secname == NULL)
        secname = "Unknown section name";

    printf("st_shndx(%u)=%s\n", sym->st_shndx, secname);

    printf("st_value=%016llx\n", OE_LLX(sym->st_value));
    printf("st_size=%llu\n", OE_LLU(sym->st_size));
    printf("\n");
}

int elf64_visit_symbols(
    const elf64_t* elf,
    int (*visit)(const elf64_sym_t* sym, void* data),
    void* data)
{
    int rc = -1;
    size_t index;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".dynsym";
    const elf64_word_t SH_TYPE = SHT_DYNSYM;

    if (!_is_valid_elf64(elf) || !visit)
        goto done;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!symtab)
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

static int _dump_symbol(const elf64_sym_t* sym, void* data)
{
    elf64_dump_symbol((elf64_t*)data, sym);
    return 0;
}

int elf64_dump_symbols(const elf64_t* elf)
{
    return elf64_visit_symbols(elf, _dump_symbol, (void*)elf);
}

void elf64_dump(const elf64_t* elf)
{
    if (!_is_valid_elf64(elf))
        return;

    elf64_dump_header(_get_header(elf));

    for (size_t i = 0; i < _get_header(elf)->e_shnum; i++)
        elf64_dump_shdr(_get_shdr(elf, i), i);

    for (size_t i = 0; i < _get_header(elf)->e_phnum; i++)
        _dump_phdr(_get_phdr(elf, i), i);
}

static size_t _find_section(const elf64_t* elf, const char* name)
{
    size_t i;

    for (i = 0; i < _get_header(elf)->e_shnum; i++)
    {
        const elf64_shdr_t* sh = _get_shdr(elf, i);
        if (sh == NULL)
            return (size_t)-1;

        const char* s = elf64_get_string_from_shstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
            return i;
    }

    return (size_t)-1;
}

int elf64_find_section(
    const elf64_t* elf,
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
    if (!_is_valid_elf64(elf) || !name || !data || !size)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _get_header(elf)->e_shnum; i++)
    {
        const elf64_shdr_t* sh = _get_shdr(elf, i);
        if (sh == NULL)
            return -1;

        const char* s = elf64_get_string_from_shstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *data = _get_section(elf, i);
            *size = sh->sh_size;
            /* The section data shouldn't be NULL */
            return *data == NULL ? -1 : 0;
        }
    }

    /* Not found! */
    return -1;
}

int elf64_find_section_header(
    const elf64_t* elf,
    const char* name,
    elf64_shdr_t* shdr)
{
    size_t i;

    if (shdr)
        memset(shdr, 0, sizeof(elf64_shdr_t));

    /* Reject invalid parameters */
    if (!_is_valid_elf64(elf) || !name || !shdr)
        return -1;

    /* Search for section with this name */
    for (i = 0; i < _get_header(elf)->e_shnum; i++)
    {
        const elf64_shdr_t* sh = _get_shdr(elf, i);
        if (sh == NULL)
            return -1;

        const char* s = elf64_get_string_from_shstrtab(elf, sh->sh_name);

        if (s && strcmp(name, s) == 0)
        {
            *shdr = *sh;
            return 0;
        }
    }

    /* Not found! */
    return -1;
}

static void _print_string_table(const char* buf, size_t size)
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
        fwrite(start, 1, (size_t)(end - start), stdout);
        printf("\"");
    }
    printf(" }\n");
}

void elf64_dump_section_names(const elf64_t* elf)
{
    if (!_is_valid_elf64(elf))
        return;

    size_t index = _get_header(elf)->e_shstrndx;
    if (index == 0)
    {
        printf("No section name table exists in ELF file.\n");
        return;
    }

    const elf64_shdr_t* sh = _get_shdr(elf, index);
    if (sh == NULL)
    {
        printf("Invalid header for section name table.\n");
        return;
    }

    const char* start = (const char*)_get_section(elf, index);
    if (start == NULL)
    {
        printf("Count not find section name table.\n");
        return;
    }

    printf("=== Section names: ");
    _print_string_table(start, sh->sh_size);
    printf("\n");
}

void elf64_dump_strings(const elf64_t* elf)
{
    if (!_is_valid_elf64(elf))
        return;

    /* Find the index of the ".strtab" section */
    size_t index;

    if ((index = _find_section(elf, ".strtab")) == (size_t)-1)
        return;

    {
        const elf64_shdr_t* sh = _get_shdr(elf, index);
        if (sh == NULL)
            return;

        const char* start = (const char*)_get_section(elf, index);
        if (start == NULL)
        {
            printf("Count not find string table.\n");
            return;
        }

        printf("=== Strings: ");
        _print_string_table(start, sh->sh_size);
        printf("\n");
    }
}

static int _is_valid_section_name(const char* s)
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
** elf64_add_section()
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

int elf64_add_section(
    elf64_t* elf,
    const char* name,
    unsigned int type,
    const void* secdata,
    size_t secsize)
{
    int rc = -1;
    size_t shstrndx;
    mem_t mem = MEM_NULL_INIT;
    elf64_shdr_t sh;

    /* Reject invalid parameters */
    if (!_is_valid_elf64(elf) || !name || !secdata || !secsize ||
        secsize > OE_SSIZE_MAX)
        GOTO(done);

    /* Fail if new section name is invalid */
    if (!_is_valid_section_name(name))
        GOTO(done);

    /* Fail if a section with this name already exits */
    if (_find_section(elf, name) != (size_t)-1)
        GOTO(done);

    /* Save index of section header string table */
    shstrndx = _get_header(elf)->e_shstrndx;

    /* For simplicity, error out if there isn't a section string table. */
    if (shstrndx == 0)
        GOTO(done);

    /* Partially initialize the section header (initialize sh.sh_name later) */
    {
        oe_memset_s(&sh, sizeof(elf64_shdr_t), 0, sizeof(elf64_shdr_t));
        sh.sh_type = type;
        sh.sh_size = secsize;
        sh.sh_addralign = 1;

        /* New section follows .shstrtab section */
        elf64_shdr_t* shdr = _get_shdr(elf, shstrndx);
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
        if (_reset_buffer(elf, &mem, sh.sh_offset, (ssize_t)secsize) != 0)
            GOTO(done);
    }

    /* Insert new section name at NAMEOFFSET */
    {
        elf64_shdr_t* shdr = _get_shdr(elf, shstrndx);
        if (shdr == NULL)
            GOTO(done);

        /* Calculate insertion offset of the new section name */
        uint64_t nameoffset = shdr->sh_offset + shdr->sh_size;

        /* Calculate number of bytes to be inserted */
        size_t namesize;
        if (oe_safe_add_sizet(strlen(name), 1, &namesize) != OE_OK)
            GOTO(done);

        namesize = oe_round_up_to_multiple(namesize, sizeof(elf64_shdr_t));

        /* Insert space for the new name */
        if (mem_insert(&mem, nameoffset, NULL, namesize) != 0)
            GOTO(done);

        /* Copy the section name to the .shstrtab section */
        oe_strlcat((char*)elf->data + nameoffset, name, namesize);

        /* Reset ELF object based on updated memory */

        if (namesize > OE_SSIZE_MAX)
            GOTO(done);

        if (_reset_buffer(elf, &mem, nameoffset, (ssize_t)namesize) != 0)
            GOTO(done);

        /* Initialize the section name */
        shdr = _get_shdr(elf, shstrndx);
        {
            sh.sh_name = (elf64_word_t)shdr->sh_size;

            /* Check for integer overflow */
            if ((elf64_xword_t)sh.sh_name != shdr->sh_size)
                GOTO(done);
        }

        /* Update the size of the .shstrtab section */
        OE_STATIC_ASSERT(sizeof(namesize) == sizeof(uint64_t));

        if (oe_safe_add_u64(
                shdr->sh_size, (uint64_t)namesize, &shdr->sh_size) != OE_OK)
            GOTO(done);
    }

    /* Append a new section header at SHDROFFSET */
    {
        /* Verify that shstrndx is within range (shdrs has grown by 1) */
        if (shstrndx > _get_header(elf)->e_shnum)
            GOTO(done);

        const char* secname = elf64_get_string_from_shstrtab(elf, sh.sh_name);
        if (!secname || strcmp(secname, name) != 0)
            GOTO(done);

        /* Insert new section header at end of data */
        if (mem_append(&mem, &sh, sizeof(elf64_shdr_t)) != 0)
            GOTO(done);

        /* Update number of sections */
        elf64_ehdr_t* ehdr = _get_header(elf);
        if (oe_safe_add_u16(ehdr->e_shnum, 1, &ehdr->e_shnum) != OE_OK)
            GOTO(done);

        /* Reset ELF object based on updated memory */
        if (_reset_buffer(elf, &mem, 0, 0) != 0)
            GOTO(done);
    }

    /* Verify that the section is exactly as expected */
    {
        const void* section =
            _get_section(elf, (size_t)(_get_header(elf)->e_shnum - 1));
        if (section == NULL)
            GOTO(done);

        if (memcmp(section, secdata, secsize) != 0)
            GOTO(done);
    }

    /* Finally verify that a section with this name exists and matches */
    {
        uint8_t* data;
        size_t size;

        if (elf64_find_section(elf, name, &data, &size) != 0)
            GOTO(done);

        if (size != secsize)
            GOTO(done);

        if (memcmp(data, secdata, size) != 0)
            GOTO(done);
    }

    rc = 0;

done:
    mem_free(&mem);
    return rc;
}

/*
**==============================================================================
**
** elf64_remove_section()
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

oe_result_t elf64_remove_section(elf64_t* elf, const char* name)
{
    size_t sec_index;
    elf64_shdr_t* shdr;
    oe_result_t result = OE_UNEXPECTED;

    /* Reject invalid parameters */
    if (!_is_valid_elf64(elf) || !name)
        goto done;

    /* Find index of this section */
    if ((sec_index = _find_section(elf, name)) == (size_t)-1)
        goto done;

    /* Save section header */
    shdr = _get_shdr(elf, sec_index);
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
        OE_CHECK(oe_memmove_s(
            first, (size_t)(end - first), last, (size_t)(end - last)));

        /* Adjust the size of the memory image */
        elf->size -= shdr->sh_size;

        /* Update affected section-related offsets */
        {
            ssize_t adjustment;

            /* Check for conversion error */
            if ((adjustment = (ssize_t)shdr->sh_size) < 0)
                goto done;

            _adjust_section_header_offsets(elf, shdr->sh_offset, -adjustment);
        }
    }

    /* Remove section name from .shsttab without changing the section size */
    {
        /* Get index of .shsttab section header */
        size_t index = _get_header(elf)->e_shstrndx;
        if (index != 0)
        {
            /* Calculate address of string */
            char* str = (char*)_get_section(elf, index);
            if (str == NULL)
                goto done;

            /* Sanity Checks. */
            elf64_shdr_t* strshdr = _get_shdr(elf, index);
            if (strshdr == NULL)
                goto done;

            if (!_is_valid_string_table(str, strshdr->sh_size))
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
        elf64_shdr_t* first = _get_shdr(elf, sec_index);
        if (first == NULL)
            goto done;

        /* Calculate end-address of section header */
        const elf64_shdr_t* last = first + 1;

        /* Calculate end-address of section headers array */
        const elf64_shdr_t* end = first + _get_header(elf)->e_shnum;

        /* Remove the header */
        OE_CHECK(oe_memmove_s(
            first,
            (size_t)(end - first) * sizeof(elf64_shdr_t),
            last,
            (size_t)(end - last) * sizeof(elf64_shdr_t)));

        /* Adjust the number of headers */
        _get_header(elf)->e_shnum--;

        /* Adjust the image size */
        elf->size -= sizeof(sizeof(elf64_shdr_t));
    }

    result = OE_OK;
done:
    return result;
}

static oe_result_t _elf64_load_relocations(
    const elf64_t* elf,
    const char* name,
    void** data_out,
    size_t* size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t index;
    elf64_shdr_t* shdr;
    uint8_t* data;
    size_t size;
    elf64_rela_t* p;
    elf64_rela_t* end;

    /* Get Shdr for the ".rela.dyn" or ".rela.plt" section */
    index = _find_shdr(elf, name);
    if (index == (size_t)-1)
    {
        *data_out = NULL;
        *size_out = 0;
        result = OE_OK;
        goto done;
    }

    /* Check invalid indexes */
    if (index == 0 || index >= _get_header(elf)->e_shnum)
        goto done;

    shdr = _get_shdr(elf, index);
    if (shdr == NULL)
        goto done;

    /* Sanity check for the entry size */
    if (shdr->sh_entsize != sizeof(elf64_rela_t))
        goto done;

    /* Get the relocation section */
    size = shdr->sh_size;
    data = _get_section(elf, index);
    if (data == NULL)
        goto done;

    /* Set pointers to start and end of relocation table */
    p = (elf64_rela_t*)data;
    end = p + (size / sizeof(elf64_rela_t));

    /* Reject unsupported relocation types */
    for (; p != end; p++)
    {
        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);
        /* The enclave doesn't perform relocations on R_X86_64_GLOB_DAT, but
         * we allow it for code that checks for the existence of weak symbols
         * before using them. */
        if (reloc_type != R_X86_64_RELATIVE && reloc_type != R_X86_64_TPOFF64 &&
            reloc_type != R_X86_64_GLOB_DAT && reloc_type != R_X86_64_64 &&
            reloc_type != R_X86_64_JUMP_SLOT)
        {
            /* Relocations are critical for correct code behavior.
             * Error out for unsupported relocations */
            OE_RAISE_MSG(
                OE_UNSUPPORTED_ENCLAVE_IMAGE,
                "Unsupported elf relocation type %d\n",
                (int)reloc_type);
        }
    }

    *data_out = data;
    *size_out = size;
    result = OE_OK;

done:
    return result;
}

oe_result_t elf64_load_relocations(
    const elf64_t* elf,
    void** data_out,
    size_t* size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    void* dyn_data = NULL;
    size_t dyn_size = 0;
    void* plt_data = NULL;
    size_t plt_size = 0;
    size_t size;
    elf64_rela_t* p;
    elf64_rela_t* end;
    const elf64_sym_t* symtab = NULL;
    size_t symtab_size = 0;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!_is_valid_elf64(elf) || !data_out || !size_out)
        goto done;

    OE_CHECK(_elf64_load_relocations(elf, ".rela.dyn", &dyn_data, &dyn_size));
    OE_CHECK(_elf64_load_relocations(elf, ".rela.plt", &plt_data, &plt_size));

    /* Ensure the size is not zero and the content of .rela.dyn is not empty */
    OE_CHECK(oe_safe_add_sizet(dyn_size, plt_size, &size));
    if (!size || !dyn_data)
    {
        /* There is no relocation information. */
        result = OE_OK;
        goto done;
    }

    /* Make a copy of the relocation section */
    *size_out = size;

    void* tmp_alloc = oe_memalign(OE_PAGE_SIZE, *size_out);
    if (!tmp_alloc)
        OE_RAISE(OE_OUT_OF_MEMORY);
    *data_out = tmp_alloc;
    tmp_alloc = NULL;

    memset(*data_out, 0, *size_out);
    OE_CHECK(oe_memcpy_s(*data_out, *size_out, dyn_data, dyn_size));
    if (plt_data)
    {
        uint64_t dst;
        size_t dst_size;
        OE_CHECK(oe_safe_add_u64((uint64_t)*data_out, dyn_size, &dst));
        OE_CHECK(oe_safe_sub_sizet(*size_out, dyn_size, &dst_size));
        OE_CHECK(oe_memcpy_s((void*)dst, dst_size, plt_data, plt_size));
    }

    /* Get pointer to symbol table */
    if (elf64_get_dynamic_symbol_table(elf, &symtab, &symtab_size))
        goto done;

    /* Fix up thread-local relocations */
    p = (elf64_rela_t*)*data_out;
    end = p + (size / sizeof(elf64_rela_t));

    for (; p != end; p++)
    {
        if (ELF64_R_TYPE(p->r_info) == R_X86_64_TPOFF64)
        {
            /* The symbol value contains the offset from the tls segment
             * end. To avoid having symbol lookup in the enclave, we store
             * the offset in the addend field. */
            uint64_t sym_index = ELF64_R_SYM(p->r_info);
            if (sym_index >= symtab_size)
            {
                OE_RAISE_MSG(
                    OE_UNSUPPORTED_ENCLAVE_IMAGE,
                    "Invalid symtab index %d\n",
                    (int)sym_index);
            }
            const elf64_sym_t* sym = &symtab[sym_index];
            p->r_addend = (elf64_sxword_t)sym->st_value;

            const char* sym_name =
                elf64_get_string_from_dynstr(elf, sym->st_name);
            OE_TRACE_INFO(
                "Relocated thread-local variable %s with offset %d\n",
                sym_name ? sym_name : "",
                (int)p->r_addend);
        }
    }

    result = OE_OK;

done:

    if (result != OE_OK)
    {
        if (size_out)
            *size_out = 0;

        if (data_out)
        {
            oe_memalign_free(*data_out);
            *data_out = NULL;
        }
    }

    return result;
}

const char* elf64_get_function_name(const elf64_t* elf, elf64_addr_t addr)
{
    const char* ret = NULL;
    size_t index;
    const elf64_shdr_t* sh;
    const elf64_sym_t* symtab;
    size_t n;
    size_t i;
    const char* SECTIONNAME = ".symtab";
    const elf64_word_t SH_TYPE = SHT_SYMTAB;

    if (!_is_valid_elf64(elf))
        goto done;

    /* Find the symbol table section header */
    index = _find_shdr(elf, SECTIONNAME);
    if (index == (size_t)-1)
        goto done;

    /* Set pointer to section header */
    sh = _get_shdr(elf, index);
    if (!sh)
        goto done;

    /* If this is not a symbol table */
    if (sh->sh_type != SH_TYPE)
        goto done;

    /* Sanity check */
    if (sh->sh_entsize != sizeof(elf64_sym_t))
        goto done;

    /* Set pointer to symbol table section */
    symtab = (const elf64_sym_t*)_get_section(elf, index);
    if (!symtab)
        goto done;

    /* Calculate number of symbol table entries */
    n = sh->sh_size / sh->sh_entsize;

    /* Look for a function symbol that contains the given address */
    for (i = 1; i < n; i++)
    {
        const elf64_sym_t* p = &symtab[i];
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
                ret = elf64_get_string_from_strtab(elf, p->st_name);
                goto done;
            }
        }
    }

done:
    return ret;
}
