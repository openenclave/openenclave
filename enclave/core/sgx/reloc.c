// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include "init.h"

#if defined(OE_USE_DSO_DYNAMIC_BINDING)
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/dynlink.h>

/* MUSL does not define an x86_64 arch-specific value for DTP_OFFSET,
 * so use the default value from musl/src/internal/pthread_impl.h */
#ifndef DTP_OFFSET
#define DTP_OFFSET 0
#endif

static inline uint64_t oe_rva_to_addr(uint64_t rva, uint64_t base)
{
    return (rva == OE_UINT64_MAX) ? 0 : (rva + base);
}

static void do_relocs(dso_t* dso, size_t* rel, size_t rel_size, size_t stride)
{
    unsigned char* base = dso->base;
    elf64_sym_t* syms = dso->syms;
    char* strings = dso->strings;
    elf64_sym_t* sym;
    const char* name;
    void* ctx;
    size_t type;
    size_t sym_index;
    symdef_t def;
    size_t* reloc_addr;
    size_t sym_val;
    size_t tls_val;
    size_t addend;
    dso_t* head = (dso_t*)oe_get_dso_head();

    /* OE simplifies the relocation logic as it does not need to handle the
     * bootstrap load of the ldso loader itself, so it does not check for
     * skipping relative relocations or resusing addends */

    for (; rel_size; rel += stride, rel_size -= stride * sizeof(size_t))
    {
        type = ELF64_R_TYPE(rel[1]);
        if (type == R_X86_64_NONE)
            continue;
        reloc_addr = laddr(dso, rel[0]);

        if (stride > 2)
        {
            addend = rel[2];
        }
        else if (
            type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT ||
            type == R_X86_64_COPY)
        {
            addend = 0;
        }
        else
        {
            addend = *reloc_addr;
        }

        sym_index = ELF64_R_SYM(rel[1]);
        if (sym_index)
        {
            sym = syms + sym_index;
            name = strings + sym->st_name;
            ctx = type == R_X86_64_COPY ? head->syms_next : head;
            def = (sym->st_info & 0xf) == STT_SECTION
                      ? (symdef_t){.dso = dso, .sym = sym}
                      : find_sym(ctx, name, type == R_X86_64_JUMP_SLOT);
            if (!def.sym &&
                (sym->st_shndx != SHN_UNDEF || sym->st_info >> 4 != STB_WEAK))
            {
                /* OE does not support lazy binding, and all enclaves
                 * should be linked with BIND_NOW, so abort the enclave
                 * if the symbol is not already loaded */
                oe_abort();
            }
        }
        else
        {
            sym = 0;
            def.sym = 0;
            def.dso = dso;
        }

        sym_val = def.sym ? (size_t)laddr(def.dso, def.sym->st_value) : 0;
        tls_val = def.sym ? def.sym->st_value : 0;

        /* MUSL has extra checks for REL_TPOFF_NEG (undefined for x86_64 arch)
         * and REL_TPOFF types that the def.dso->tls_id does not exceed the
         * static_tls_cnt at runtime. That check is tautological for OE as
         * static_tls_cnt is defined after all immediate bind relocs
         * have occurred, but this is the  responsible for immediate binding
         * in OE enclaves. */

        switch (type)
        {
            case R_X86_64_NONE:
                break;
            /* REL_OFFSET is undefined for x86_64 */
            case R_X86_64_64:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                *reloc_addr = sym_val + addend;
                break;
            case R_X86_64_RELATIVE:
                *reloc_addr = (size_t)base + addend;
                break;
            /* REL_SYM_OR_REL is undefined for x86_64 */
            case R_X86_64_COPY:
                memcpy(reloc_addr, (void*)sym_val, sym->st_size);
                break;
            case R_X86_64_PC32:
                *(uint32_t*)reloc_addr =
                    (uint32_t)(sym_val + addend - (size_t)reloc_addr);
                break;
            /* REL_FUNCDESC is undefined for x86_64 */
            /* REL_FUNCDESC_VAL is undefined for x86_64 */
            /* REL_DTPMOD64/REL_DTPOFF64 can work but are untested */
            case R_X86_64_DTPMOD64:
                *reloc_addr = def.dso->tls_id;
                break;
            case R_X86_64_DTPOFF64:
                *reloc_addr = tls_val + addend - DTP_OFFSET;
                break;
            case R_X86_64_TPOFF64:
                *reloc_addr = tls_val - def.dso->tls.offset + addend;
                break;
            /* REL_TPOFF_NEG is undefined for x86_64 */
            /* REL_TLSDESC is not currently supported by OE as it requires
             * dynamic allocations of TLS */
            default:
                /* Unsupported relocation found, abort the enclave */
                oe_abort();
        }
    }
}

static void _reloc_all(dso_t* p)
{
    size_t dyn[DYN_CNT];
    for (; p; p = p->next)
    {
        if (p->relocated)
            continue;
        decode_vec(p->dynv, dyn, DYN_CNT);
        do_relocs(
            p,
            (size_t*)laddr(p, dyn[DT_JMPREL]),
            dyn[DT_PLTRELSZ],
            2 + (dyn[DT_PLTREL] == DT_RELA));
        do_relocs(p, (size_t*)laddr(p, dyn[DT_REL]), dyn[DT_RELSZ], 2);
        do_relocs(p, (size_t*)laddr(p, dyn[DT_RELA]), dyn[DT_RELASZ], 3);
        p->relocated = 1;
    }
}

/*
**==============================================================================
**
** _oe_reloc_dso()
**
**     Apply symbol relocations using the dso_t info from the host loader
**     over all enclave modules. The dso_t data block is measured as part of
**     the enclave signature (MRENCLAVE).
**
**==============================================================================
*/
static bool _oe_reloc_dso()
{
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
    uint64_t dso_base = (uint64_t)oe_get_dso_head();
    dso_t* dso_head = (dso_t*)dso_base;
    dso_t* syms_tail = dso_head;

    /* Find & rehydrate the DSO data structures */
    for (dso_t* p = dso_head; p; p = p->next)
    {
        dso_ref_t* p_ref = (dso_ref_t*)p;

        p->base = (unsigned char*)baseaddr + p_ref->seg_rva;
        p->prev = (dso_t*)oe_rva_to_addr(p_ref->prev_rva, dso_base);
        p->next = (dso_t*)oe_rva_to_addr(p_ref->next_rva, dso_base);
        p->needed_by = (dso_t*)oe_rva_to_addr(p_ref->needed_by_rva, dso_base);

        p->dynv = (size_t*)(p->base + p_ref->dyn_rva);
        p->phdr = (elf64_phdr_t*)(p->base + p_ref->phdr_rva);
        /* p->phnum does not require fixup */

        /* decode_dyn fixes these fields given the updated base and dynv:
         *   elf64_sym_t_t* syms;
         *   elf_symndx_t* hashtab;
         *   uint32_t* ghashtab;
         *   int16_t* versym;
         *   char* strings;
         *   size_t* got; */
        decode_dyn(p);

        /* Fixup TLS image pointer.
         * Note that tls_id and tls members (len, align, offset, size)
         * do not require fixups */
        p->tls.image = (void*)oe_rva_to_addr(
            (uint64_t)p_ref->tls.image, (uint64_t)p->base);

        /* The following are set later as part of relocs */
        // char relocated;
        // char constructed;

        /* The following are unused and do not need to be populated
         * on the enclave side */
        // unsigned char* map;
        // size_t map_len;
        // loadmap_t* loadmap;
        // uint64_t entry_rva;

        /* These require no fixups */
        // uint64_t self_rva;
        // uint64_t seg_rva;

        /* Name strings are explicitly unsupported in OE for now
         * as they break ability to rename the primary enclave */
        // p->name = (char*)p_ref + sizeof(dso_t);
        // p->shortname += (uint64_t)p->name;
        // char buf[];
    }

    /* syms_next is populated in the enclave only as it is
     * deterministic given the dso_t linked list. If dynamic loading is
     * to be supported, functions to add and remove syms from the list
     * would also be the enclave's responsibility, and so OE handles it
     * here to elide marshalling the values as RVAs from the host.
     */
    for (dso_t* p = dso_head; p; p = p->next)
    {
        if (!p->syms_next && syms_tail != p)
        {
            syms_tail->syms_next = p;
            syms_tail = p;
        }
    }

    /* The main program must be relocated LAST since it may contain
     * copy relocations which depend on libraries' relocations. */
    _reloc_all(dso_head->next);
    _reloc_all(dso_head);

    return true;
}
#else
/*
**==============================================================================
**
** _oe_reloc_single_image()
**
**     Apply symbol relocations from the relocation pages, whose content
**     was copied from the ELF file during loading. These relocations are
**     included in the enclave signature (MRENCLAVE).
**
**==============================================================================
*/

static bool _oe_reloc_single_image(void)
{
    const elf64_rela_t* relocs = (const elf64_rela_t*)__oe_get_reloc_base();
    size_t nrelocs = __oe_get_reloc_size() / sizeof(elf64_rela_t);
    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();

    for (size_t i = 0; i < nrelocs; i++)
    {
        const elf64_rela_t* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        if (reloc_type == R_X86_64_RELATIVE)
        {
            *dest = (uint64_t)(baseaddr + p->r_addend);
        }
    }

    return true;
}
#endif

bool oe_apply_relocations(void)
{
#if defined(OE_USE_DSO_DYNAMIC_BINDING)
    return _oe_reloc_dso();
#else
    return _oe_reloc_single_image();
#endif
}
