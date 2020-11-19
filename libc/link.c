// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <elf.h>
#include <link.h>
#include <openenclave/internal/globals.h>
#include <stdio.h>
#include <string.h>

#if defined(OE_USE_DSO_DYNAMIC_BINDING)
#include <openenclave/internal/dynlink.h>
#endif

/* Used by libunwind to iterate program ELF phdrs */
int dl_iterate_phdr(
    int (*callback)(struct dl_phdr_info* info, size_t size, void* data),
    void* data)
{
#if defined(OE_USE_DSO_DYNAMIC_BINDING)
    dso_t* head = (dso_t*)oe_get_dso_head();
    struct dl_phdr_info info = {0};
    int ret = 0;

    /* Note that OE does not support dynamic loading and so the
     * DSO linked list is expected to be constant in the enclave.
     * Compared to the MUSL implementation, this means that:
     *   - iteration of the linked list is not guarded by mutex
     *   - dlpi_adds is always 0 as the count of dynamically added DSOs.
     */
    for (dso_t* current = head; current; current = current->next)
    {
        info.dlpi_addr = (uintptr_t)current->base;
        info.dlpi_name = current->name;
        info.dlpi_phdr = (Elf64_Phdr*)current->phdr;
        info.dlpi_phnum = current->phnum;
        info.dlpi_adds = 0;
        info.dlpi_subs = 0;
        info.dlpi_tls_modid = current->tls_id;
        info.dlpi_tls_data = current->tls.image;

        ret = (callback)(&info, sizeof(info), data);

        if (ret != 0)
            break;
    }
    return ret;
#else
    const Elf64_Ehdr* ehdr = (Elf64_Ehdr*)__oe_get_enclave_elf_header();

    const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};

    if (memcmp(ehdr->e_ident, ident, sizeof(ident)) != 0)
    {
        assert("dl_iterate_phdr(): bad identifier" == NULL);
        return -1;
    }

    struct dl_phdr_info info;
    memset(&info, 0, sizeof(info));
    info.dlpi_addr = (Elf64_Addr)__oe_get_enclave_base();
    info.dlpi_name = "";
    info.dlpi_phdr = (Elf64_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff);
    info.dlpi_phnum = ehdr->e_phnum;

    return callback(&info, sizeof(info), data);
#endif
}
