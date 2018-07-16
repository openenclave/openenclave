// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/backtrace_symbols.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include "enclave.h"

char** oe_backtrace_symbols(
    oe_enclave_t* enclave,
    void* const* buffer,
    int size)
{
    char** ret = NULL;
    Elf64 elf = ELF64_INIT;
    bool elf_loaded = false;

    if (!enclave || enclave->magic != ENCLAVE_MAGIC || !buffer || !size)
        goto done;

    /* Open the enclave ELF64 image */
    {
        if (Elf64_Load(enclave->path, &elf) != 0)
            goto done;

        elf_loaded = true;
    }

    if (!(ret = (char**)calloc(size, sizeof(char*))))
        goto done;

    for (int i = 0; i < size; i++)
    {
        /* Convert to virtual address */
        const uint64_t addr = (uint64_t)buffer[i] - enclave->addr;
        const char* name = Elf64_GetFunctionName(&elf, addr);

        if (name)
            ret[i] = (char*)name;
        else
            ret[i] = "<unknown>";
    }

done:

    if (elf_loaded)
        Elf64_Unload(&elf);

    return ret;
}
