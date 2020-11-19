// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/dynlink.h>
#include <openenclave/internal/elf.h>
#include "../common.h"

/* 3rdparty/musl/musl/arch/x86_64/bits/stdint.h defines:
 *    typedef uint32_t uint_fast32_t;
 * but host-side /usr/include/stdint.h defines it as unsigned long on x64.
 * Explicitly typedef this as uint32_t per MUSL intent. */
typedef uint32_t musl_uint_fast32_t;

#define OK_TYPES                                                           \
    (1 << STT_NOTYPE | 1 << STT_OBJECT | 1 << STT_FUNC | 1 << STT_COMMON | \
     1 << STT_TLS)
#define OK_BINDS (1 << STB_GLOBAL | 1 << STB_WEAK | 1 << STB_GNU_UNIQUE)

/* Logically unmodified helpers from MUSL dynlink.c */
void decode_vec(size_t* v, size_t* a, size_t cnt)
{
    size_t i;
    for (i = 0; i < cnt; i++)
        a[i] = 0;
    for (; v[0]; v += 2)
        if (v[0] - 1 < cnt - 1)
        {
            a[0] |= 1UL << v[0];
            a[v[0]] = v[1];
        }
}

int search_vec(size_t* v, size_t* r, size_t key)
{
    for (; v[0] != key; v += 2)
        if (!v[0])
            return 0;
    *r = v[1];
    return 1;
}

static uint32_t gnu_hash(const char* s0)
{
    const unsigned char* s = (void*)s0;
    musl_uint_fast32_t h = 5381;
    for (; *s; s++)
        h += h * 32 + *s;
    return h;
}

static uint32_t sysv_hash(const char* s0)
{
    const unsigned char* s = (void*)s0;
    musl_uint_fast32_t h = 0;
    while (*s)
    {
        h = 16 * h + *s++;
        h ^= h >> 24 & 0xf0;
    }
    return h & 0xfffffff;
}

/* Slightly modified MUSL dynlink.c methods, such as removal of unused #ifdef
 * codepaths and substituting libc typedefs with OE equivalents (e.g. dso_t).
 * Logical deviations are called out in comments in the implementations. */

void decode_dyn(dso_t* p)
{
    size_t dyn[DYN_CNT];
    decode_vec(p->dynv, dyn, DYN_CNT);
    p->syms = laddr(p, dyn[DT_SYMTAB]);
    p->strings = laddr(p, dyn[DT_STRTAB]);
    if (dyn[0] & (1 << DT_HASH))
        p->hashtab = laddr(p, dyn[DT_HASH]);
    /* NOTE: OE elides setting p->rpath_orig from DT_RPATH/DT_RUNPATH per MUSL
     * as OE does not currently support dynamic loading and path lookups */
    if (dyn[0] & (1 << DT_PLTGOT))
        p->got = laddr(p, dyn[DT_PLTGOT]);
    if (search_vec(p->dynv, dyn, DT_GNU_HASH))
        p->ghashtab = laddr(p, *dyn);
    if (search_vec(p->dynv, dyn, DT_VERSYM))
        p->versym = laddr(p, *dyn);
}

static elf64_sym_t* gnu_lookup(
    uint32_t h1,
    uint32_t* hashtab,
    dso_t* dso,
    const char* s)
{
    uint32_t nbuckets = hashtab[0];
    uint32_t* buckets = hashtab + 4 + hashtab[2] * (sizeof(size_t) / 4);
    uint32_t i = buckets[h1 % nbuckets];

    if (!i)
        return 0;

    uint32_t* hashval = buckets + nbuckets + (i - hashtab[1]);

    for (h1 |= 1;; i++)
    {
        uint32_t h2 = *hashval++;
        if ((h1 == (h2 | 1)) && (!dso->versym || dso->versym[i] >= 0) &&
            !oe_strcmp(s, dso->strings + dso->syms[i].st_name))
            return dso->syms + i;
        if (h2 & 1)
            break;
    }

    return 0;
}

static elf64_sym_t* gnu_lookup_filtered(
    uint32_t h1,
    uint32_t* hashtab,
    dso_t* dso,
    const char* s,
    uint32_t fofs,
    size_t fmask)
{
    const size_t* bloomwords = (const void*)(hashtab + 4);
    size_t f = bloomwords[fofs & (hashtab[2] - 1)];
    if (!(f & fmask))
        return 0;

    f >>= (h1 >> hashtab[3]) % (8 * sizeof f);
    if (!(f & 1))
        return 0;

    return gnu_lookup(h1, hashtab, dso, s);
}

static elf64_sym_t* sysv_lookup(const char* s, uint32_t h, dso_t* dso)
{
    size_t i;
    elf64_sym_t* syms = dso->syms;
    elf_symndx_t* hashtab = dso->hashtab;
    char* strings = dso->strings;
    for (i = hashtab[2 + h % hashtab[0]]; i; i = hashtab[2 + hashtab[0] + i])
    {
        if ((!dso->versym || dso->versym[i] >= 0) &&
            (!oe_strcmp(s, strings + syms[i].st_name)))
            return syms + i;
    }
    return 0;
}

symdef_t find_sym(dso_t* dso, const char* s, int need_def)
{
    uint32_t h = 0, gh = gnu_hash(s), gho = gh / (8 * sizeof(size_t)), *ght;
    size_t ghm = 1ul << gh % (8 * sizeof(size_t));
    symdef_t def = {0};
    for (; dso; dso = dso->syms_next)
    {
        elf64_sym_t* sym;
        if ((ght = dso->ghashtab))
        {
            sym = gnu_lookup_filtered(gh, ght, dso, s, gho, ghm);
        }
        else
        {
            if (!h)
                h = sysv_hash(s);
            sym = sysv_lookup(s, h, dso);
        }
        if (!sym)
            continue;
        if (!sym->st_shndx)
            if (need_def || (sym->st_info & 0xf) == STT_TLS)
                /* NOTE: OE does not need to handle MIPS arch and
                 * ARCH_SYM_REJECT_UND(sym) */
                continue;
        if (!sym->st_value)
            if ((sym->st_info & 0xf) != STT_TLS)
                continue;
        if (!(1 << (sym->st_info & 0xf) & OK_TYPES))
            continue;
        if (!(1 << (sym->st_info >> 4) & OK_BINDS))
            continue;
        def.sym = sym;
        def.dso = dso;
        break;
    }
    return def;
}
