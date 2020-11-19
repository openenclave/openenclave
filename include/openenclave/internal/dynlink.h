// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_DYNLINK_H
#define _OE_DYNLINK_H

#include <openenclave/bits/result.h>
#include <openenclave/internal/elf.h> // elf64_sym_t, elf64_phdr_t

/* NOTE: MUSL uses these restrictions in their implementation, which we
 * can keep for simplicity, but doesn't seem to be documented as a
 * de facto part of ELF loading anywhere */
#define DYN_CNT 32

#define MIN_TLS_ALIGN 8

/* Defined in accordance with openenclave/include/corelibc/limits.h */
#define NAME_MAX 255

#ifndef OE_BUILD_ENCLAVE
#define PAGE_SIZE ((size_t)OE_PAGE_SIZE)
#endif

#define laddr(p, v) (void*)((p)->base + (v))
#define rvaddr(p, l) (uint6t_t)((l) - (p)->base))
#define fpaddr(p, v) ((void (*)())laddr(p, v))

typedef struct _tls_module
{
    /* Unlike MUSL, OE does not track the TLS linked list
     * needed for TLS support in dynamic loading yet. */
    void* image;
    size_t len, size, align, offset;
} tls_module_t;

typedef struct _loadseg
{
    uint64_t addr, p_vaddr, p_memsz;
    uint32_t p_flags;
} loadseg_t;

typedef struct _loadmap
{
    size_t nsegs;
    loadseg_t segs[];
} loadmap_t;

typedef struct _dso
{
    char* name;
    unsigned char* base;
    size_t* dynv;
    struct _dso *next, *prev;

    elf64_phdr_t* phdr;
    int phnum;
    elf64_sym_t* syms;
    elf_symndx_t* hashtab;
    uint32_t* ghashtab;
    int16_t* versym;
    char* strings;
    struct _dso* syms_next;
    unsigned char* map;
    size_t map_len;
    char relocated;
    char constructed;
    struct _dso* needed_by;
    tls_module_t tls;
    size_t tls_id;
    struct _dso* fini_next;
    char* shortname;
    loadmap_t* loadmap; // NOTE: Analogous to existing OE image.segments
    size_t* got;

    /* OE added RVA fields */
    uint64_t entry_rva;  /* Added by OE for parity with _oe_enclave_elf_image */
    uint64_t self_rva;   /* RVA for this dso_t in enclave address space */
    uint64_t seg_rva;    /* RVA of the DSO added in enclave address space */
    uint64_t oeinfo_rva; /* RVA of .oeinfo section, if present */
    uint64_t oeinfo_file_pos; /* File offset of .oeinfo section, if present */

    char buf[]; // Null-terminated buffer that name/shortname points to
} dso_t;

typedef struct _dso_ref
{
    char* name;                  // Unused in enclave
    unsigned char* base;         // Repopulated in enclave based on seg_rva
    uint64_t dyn_rva;            // Marshalled as RVA into enclave
    uint64_t next_rva, prev_rva; // Marshalled as RVA into enclave

    uint64_t phdr_rva;      // Marshalled as RVA into enclave
    int phnum;              // Copied to enclave, no fixup needed
    elf64_sym_t* syms;      // Repopulated by decode_dyn based on base & dynv
    elf_symndx_t* hashtab;  // Repopulated by decode_dyn based on base & dynv
    uint32_t* ghashtab;     // Repopulated by decode_dyn based on base & dynv
    int16_t* versym;        // Repopulated by decode_dyn based on base & dynv
    char* strings;          // Repopulated by decode_dyn based on base & dynv
    struct _dso* syms_next; // Only populated in the enclave
    unsigned char* map;     // Unused in enclave
    size_t map_len;         // Unused in enclave
    char relocated;         // Only populated in the enclave
    char constructed;       // Only populated in the enclave
    uint64_t needed_by_rva; // Marshalled as RVA into enclave
    tls_module_t tls;       /* tls.image marshalled as RVA into enclave,
                               other members copied as-is, no fix-up needed */
    size_t tls_id;          // Copied to enclave, no fixup needed
    struct _dso* fini_next; // Only populated in the enclave
    char* shortname;        // Unused in enclave
    loadmap_t* loadmap;     // Unused in enclave
    size_t* got;            // Repopulated by decode_dyn based on base & dynv

    /* OE added RVA fields */
    uint64_t entry_rva;       // Unused in enclave
    uint64_t oeinfo_rva;      // Unused in enclave
    uint64_t oeinfo_file_pos; // Unused in enclave
    uint64_t self_rva;        // Copied to enclave, no fixup needed
    uint64_t seg_rva;         // Copied to enclave, no fixup needed

    char buf[]; // Unused in enclave
} dso_ref_t;

OE_STATIC_ASSERT(sizeof(dso_ref_t) == sizeof(dso_t));
typedef struct _symdef
{
    elf64_sym_t* sym;
    dso_t* dso;
} symdef_t;

typedef struct _oe_dso_load_state
{
    dso_t* head;
    dso_t* tail;
    size_t segments_size;
    size_t tls_cnt;
    size_t tls_offset;
    size_t tls_align;
} oe_dso_load_state_t;

oe_result_t oe_load_enclave_dso(
    const char* name,
    oe_dso_load_state_t* load_state,
    dso_t* needed_by,
    dso_t** dso);

void oe_unload_enclave_dso(oe_dso_load_state_t* load_state);

oe_result_t oe_load_deps(oe_dso_load_state_t* load_state, dso_t* p);

size_t oe_get_dso_size(dso_t* dso);

size_t oe_get_dso_segments_size(dso_t* dso);

/* Common dynlink functions adapted from MUSL */
void decode_dyn(dso_t* p);
void decode_vec(size_t* v, size_t* a, size_t cnt);
int search_vec(size_t* v, size_t* r, size_t key);
symdef_t find_sym(dso_t* dso, const char* s, int need_def);

#endif /* _OE_DYNLINK_H */