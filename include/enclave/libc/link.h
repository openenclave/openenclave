#ifndef __ELIBC_LINK_H
#define __ELIBC_LINK_H

#include <features.h>
#include <bits/alltypes.h>
#include <elf.h>

__ELIBC_BEGIN

struct dl_phdr_info
{
    Elf64_Addr dlpi_addr;
    const char *dlpi_name;
    const Elf64_Phdr *dlpi_phdr;
    Elf64_Half dlpi_phnum;
    unsigned long long int dlpi_adds;
    unsigned long long int dlpi_subs;
    size_t dlpi_tls_modid;
    void *dlpi_tls_data;
};

int dl_iterate_phdr(
    int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
    void *data);

__ELIBC_END

#endif /* __ELIBC_LINK_H */
