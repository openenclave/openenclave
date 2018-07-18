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
    size_t malloc_size = 0;
    const char unknown[] = "<unknown>";
    char* ptr = NULL;

    if (!enclave || enclave->magic != ENCLAVE_MAGIC || !buffer || !size)
        goto done;

    /* Open the enclave ELF64 image */
    {
        if (Elf64_Load(enclave->path, &elf) != 0)
            goto done;

        elf_loaded = true;
    }

    /* Determine total memory requirements */
    {
        /* Calculate space for the array of string pointers */
        malloc_size = size * sizeof(char*);

        /* Calculate space for each string */
        for (int i = 0; i < size; i++)
        {
            const uint64_t vaddr = (uint64_t)buffer[i] - enclave->addr;
            const char* name = Elf64_GetFunctionName(&elf, vaddr);

            if (!name)
                name = unknown;

            malloc_size += strlen(name) + sizeof(char);
        }
    }

    /* Allocate the array of string pointers, followed by the strings */
    if (!(ptr = (char*)malloc(malloc_size)))
        goto done;

    /* Set pointer to array of strings */
    ret = (char**)ptr;

    /* Skip over array of strings */
    ptr += size * sizeof(char*);

    /* Copy strings into return buffer */
    for (int i = 0; i < size; i++)
    {
        const uint64_t vaddr = (uint64_t)buffer[i] - enclave->addr;
        const char* name = Elf64_GetFunctionName(&elf, vaddr);

        if (!name)
            name = unknown;

        size_t name_size = strlen(name) + sizeof(char);
        memcpy(ptr, name, name_size);
        ret[i] = ptr;
        ptr += name_size;
    }

done:

    if (elf_loaded)
        Elf64_Unload(&elf);

    return ret;
}
