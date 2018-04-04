// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ELF_H
#define _OE_ELF_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
#define ELF_EXTERNC_BEGIN extern "C" {
#define ELF_EXTERNC_END }
#else
#define ELF_EXTERNC_BEGIN
#define ELF_EXTERNC_END
#endif

ELF_EXTERNC_BEGIN

#define EI_NIDENT 16

/* Elf64_Ehdr.e_ident */
#define EI_MAG0 0    /* File identification */
#define EI_MAG1 1    /* File identification */
#define EI_MAG2 2    /* File identification */
#define EI_MAG3 3    /* File identification */
#define EI_CLASS 4   /* File class */
#define EI_DATA 5    /* Data encoding */
#define EI_VERSION 6 /* File version */
#define EI_PAD 7     /* Start of padding bytes */
#define EI_NIDENT 16 /* Size of e_ident[] */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASSNONE 0 /* Invalid class */
#define ELFCLASS32 1   /* 32-bit objects e_ident[EI_CLASS] */
#define ELFCLASS64 2   /* 64-bit objects */
#define ELFDATANONE 0  /* Invalid data encoding */
#define ELFDATA2LSB 1  /* See below */
#define ELFDATA2MSB 2  /* See below */

/* Elf64_Ehdr.e_type */
#define ET_NONE 0        /* no file */
#define ET_REL 1         /* relocatable file */
#define ET_EXEC 2        /* executable file */
#define ET_DYN 3         /* shared object file */
#define ET_CORE 4        /* core file */
#define ET_LOPROC 0xff00 /* processor-specific */
#define ET_HIPROC 0xffff /* processor-specific */

/* Elf64_Ehdr.e_machine */
#define EM_NONE 0    /* no machine */
#define EM_M32 1     /* AT&T WE 32100 */
#define EM_SPARC 2   /* SPARC */
#define EM_386 3     /* Intel 80386 */
#define EM_68K 4     /* Motorola 68000 */
#define EM_88K 5     /* Motorola 88000 */
#define EM_860 7     /* Intel 80860 */
#define EM_MIPS 8    /* MIPS RS3000 */
#define EM_X86_64 62 /* Intel X86-64 */

/* Elf64_Ehdr.e_version */
#define EV_NONE 0    /* Invalid version */
#define EV_CURRENT 1 /* Current version */

/* Elf64_Ehdr.e_shstrndx */
#define SHN_UNDEF 0
#define SHN_LORESERVE 0xff00
#define SHN_LOPROC 0xff00
#define SHN_HIPROC 0xff1f
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff

/* Elf64_Shdr.sh_type */
#define SHT_NULL 0          /* Marks an unused section header */
#define SHT_PROGBITS 1      /* information defined by the program */
#define SHT_SYMTAB 2        /* linker symbol table */
#define SHT_STRTAB 3        /* string table */
#define SHT_RELA 4          /* "Rela" type relocation entries */
#define SHT_HASH 5          /* a symbol hash table */
#define SHT_DYNAMIC 6       /* dynamic linking tables */
#define SHT_NOTE 7          /* 7 note information */
#define SHT_NOBITS 8        /* Uninitialized space; no space in the file */
#define SHT_REL 9           /* "Rel" type relocation entries */
#define SHT_SHLIB 10        /* Reserved */
#define SHT_DYNSYM 11       /* a dynamic loader symbol table */
#define SHT_LOOS 0x60000000 /* Environment-specific use */
#define SHT_HIOS 0x6FFFFFFF
#define SHT_LOPROC 0x70000000 /* Processor-specific use */
#define SHT_HIPROC 0x7FFFFFFF

#define PT_NULL 0          /* Unused entry */
#define PT_LOAD 1          /* Loadable segment */
#define PT_DYNAMIC 2       /* Dynamic linking tables */
#define PT_INTERP 3        /* Program interpreter path name */
#define PT_NOTE 4          /* Note sections */
#define PT_SHLIB 5         /* Reserved */
#define PT_PHDR 6          /* Program header table */
#define PT_TLS 7           /* Thread local storage segment */
#define PT_LOOS 0x60000000 /* Environment-specific use */
#define PT_HIOS 0x6FFFFFFF
#define PT_LOPROC 0x70000000 /* Processor-specific use */
#define PT_HIPROC 0x7FFFFFFF

#define SHF_WRITE 0x1     /* Section contains writable data */
#define SHF_ALLOC 0x2     /* Section is allocated in memory image of program */
#define SHF_EXECINSTR 0x4 /* Section contains executable instructions */
#define SHF_MASKOS 0x0F000000   /* Environment-specific use */
#define SHF_MASKPROC 0xF0000000 /* Processor-specific use */

#define PF_X 0x1               /* Execute permission */
#define PF_W 0x2               /* Write permission */
#define PF_R 0x4               /* Read permission */
#define PF_MASKOS 0x00FF0000   /* environment-specific use */
#define PF_MASKPROC 0xFF000000 /* processor-specific use */

#define STB_LOCAL 0  /* Not visible outside the object file */
#define STB_GLOBAL 1 /* Global symbol, visible to all object files */
#define STB_WEAK 2   /* Global scope, but with lower precedence than globals */
#define STB_LOOS 10  /* Environment-specific use */
#define STB_HIOS 12
#define STB_LOPROC 13 /* Processor-specific use */
#define STB_HIPROC 15

#define STT_NOTYPE 0  /* No type specified (e.g., an absolute symbol) */
#define STT_OBJECT 1  /* Data object */
#define STT_FUNC 2    /* Function entry point */
#define STT_SECTION 3 /* Symbol is associated with a section */
#define STT_FILE 4    /* Source file associated with the object file */
#define STT_LOOS 10   /* Environment-specific use */
#define STT_HIOS 12
#define STT_LOPROC 13 /* Processor-specific use */
#define STT_HIPROC 15

/* Elf64_Rel.r_info */
#define R_X86_64_RELATIVE 8
#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i)&0xffffffffL)
#define ELF64_R_INFO(s, t) (((s) << 32) + ((t)&0xffffffffL))

typedef unsigned long long Elf64_Addr;
typedef unsigned long long Elf64_Off;
typedef unsigned short Elf64_Half;
typedef unsigned int Elf64_Word;
typedef signed int Elf64_Sword;
typedef unsigned long long Elf64_Xword;
typedef signed long long Elf64_Sxword;
typedef signed int Elf64_Sword;

typedef struct
{
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;     /* entry point virtual address */
    Elf64_Off e_phoff;      /* program header table offset */
    Elf64_Off e_shoff;      /* (40) section header tabble offset */
    Elf64_Word e_flags;     /* process-specific flags */
    Elf64_Half e_ehsize;    /* ELF header size */
    Elf64_Half e_phentsize; /* Program header table entry size */
    Elf64_Half e_phnum;     /* Number of program header table entries */
    Elf64_Half e_shentsize; /* Section header size */
    Elf64_Half e_shnum;     /* Number of section headers */
    Elf64_Half e_shstrndx;  /* Index of the string-table section header */
} Elf64_Ehdr;

typedef struct
{
    Elf64_Word sh_name;       /* Section name */
    Elf64_Word sh_type;       /* Section type */
    Elf64_Xword sh_flags;     /* Section attributes */
    Elf64_Addr sh_addr;       /* Virtual address in memory */
    Elf64_Off sh_offset;      /* Offset in file */
    Elf64_Xword sh_size;      /* Size of section */
    Elf64_Word sh_link;       /* Link to other section */
    Elf64_Word sh_info;       /* Miscellaneous information */
    Elf64_Xword sh_addralign; /* Address alignment boundary */
    Elf64_Xword sh_entsize;   /* Size of entries, if section has table */
} Elf64_Shdr;

typedef struct
{
    Elf64_Word p_type;    /* Type of segment */
    Elf64_Word p_flags;   /* Segment attributes */
    Elf64_Off p_offset;   /* Offset in file */
    Elf64_Addr p_vaddr;   /* Virtual address in memory */
    Elf64_Addr p_paddr;   /* Reserved */
    Elf64_Xword p_filesz; /* Size of segment in file */
    Elf64_Xword p_memsz;  /* Size of segment in memory */
    Elf64_Xword p_align;  /* Alignment of segment */
} Elf64_Phdr;

typedef struct
{
    Elf64_Word st_name;     /* Symbol name */
    unsigned char st_info;  /* Type and Binding attributes */
    unsigned char st_other; /* Reserved */
    Elf64_Half st_shndx;    /* Section table index */
    Elf64_Addr st_value;    /* Symbol value */
    Elf64_Xword st_size;    /* Size of object (e.g., common) */
} Elf64_Sym;

typedef struct
{
    Elf64_Addr r_offset; /* Address of reference */
    Elf64_Xword r_info;  /* Symbol index and type of relocation */
} Elf64_Rel;

typedef struct
{
    Elf64_Addr r_offset;   /* Address of reference */
    Elf64_Xword r_info;    /* Symbol index and type of relocation */
    Elf64_Sxword r_addend; /* Constant part of expression */
} Elf64_Rela;

#define ELF_MAGIC 0x7d7ad33b
#define ELF64_INIT                                 \
    {                                              \
        ELF_MAGIC, NULL, 0, NULL, NULL, NULL, NULL \
    }

typedef struct
{
    /* Magic number (ELF_MAGIC) */
    unsigned int magic;

    /* File image */
    void* data;

    /* File image size */
    size_t size;

    /* ELF-64 header */
    Elf64_Ehdr* ehdr;

    /* Pointer to ehdr.e_shnum section headers */
    Elf64_Shdr* shdrs;

    /* Array of pointers to ehdr.e_shnum sections */
    void** sections;

    /* Pointer to ehdr.e_phnum program headers */
    Elf64_Phdr* phdrs;

    /* Array of pointers to ehdr.e_phnum segments */
    void** segments;
} Elf64;

int Elf64_TestHeader(const Elf64_Ehdr* header);

int Elf64_Load(const char* path, Elf64* elf);

int Elf64_Unload(Elf64* elf);

const void* Elf64_GetSymbolTableSection(const Elf64* elf);

void Elf64_DumpHeader(const Elf64_Ehdr* ehdr);

void Elf64_DumpShdr(const Elf64_Shdr* sh, size_t index);

void Elf64_Dump(const Elf64* elf);

int Elf64_DumpSections(const Elf64* elf);

void Elf64_DumpSymbol(const Elf64* elf, const Elf64_Sym* sym);

int Elf64_DumpSymbols(const Elf64* elf);

int Elf64_FindSymbolByName(const Elf64* elf, const char* name, Elf64_Sym* sym);

const char* Elf64_GetStringFromDynstr(const Elf64* elf, Elf64_Word offset);

int Elf64_FindDynamicSymbolByName(
    const Elf64* elf,
    const char* name,
    Elf64_Sym* sym);

int Elf64_FindDynamicSymbolByAddress(
    const Elf64* elf,
    Elf64_Addr addr,
    unsigned int type, /* STT_? */
    Elf64_Sym* sym);

int Elf64_FindSymbolByAddress(
    const Elf64* elf,
    Elf64_Addr addr,
    unsigned int type, /* STT_? */
    Elf64_Sym* sym);

int Elf64_FindSection(
    const Elf64* elf,
    const char* name,
    const void** data,
    size_t* size);

const char* Elf64_GetStringFromShstrtab(const Elf64* elf, Elf64_Word offset);

const char* Elf64_GetStringFromStrtab(const Elf64* elf, Elf64_Word offset);

int Elf64_AddSection(
    Elf64* elf,
    const char* name,
    unsigned int type,
    const void* secdata,
    size_t secsize);

int Elf64_RemoveSection(
    Elf64* elf,
    const char* name);

void Elf64_DumpSectionNames(const Elf64* elf);

void Elf64_DumpStrings(const Elf64* elf);

int Elf64_FindSectionHeader(
    const Elf64* elf,
    const char* name,
    Elf64_Shdr* shdr);

int Elf64_VisitSymbols(
    const Elf64* elf,
    int (*visit)(const Elf64_Sym* sym, void* data),
    void* data);

/* Load relocations (size will be a multiple of the page size) */
int Elf64_LoadRelocations(const Elf64* elf, void** data, size_t* size);

ELF_EXTERNC_END

#endif /* _OE_ELF_H */
