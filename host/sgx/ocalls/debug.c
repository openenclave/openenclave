// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/argv.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>

#include "../enclave.h"
#include "openenclave/internal/trace.h"
#include "openenclave/log.h"
#include "platform_u.h"

static char** _backtrace_symbols(
    oe_enclave_t* enclave,
    void* const* buffer,
    int size)
{
    char** ret = NULL;

    elf64_t elf = ELF64_INIT;
    bool elf_loaded = false;
    size_t malloc_size = 0;
    const char unknown[] = "<unknown>";
    char* ptr = NULL;

    if (!enclave || enclave->magic != ENCLAVE_MAGIC || !buffer || !size)
        goto done;

    /* Open the enclave ELF64 image */
    {
        if (elf64_load(enclave->path, &elf) != 0)
            goto done;

        elf_loaded = true;
    }

    /* Determine total memory requirements */
    {
        /* Calculate space for the array of string pointers */
        if (oe_safe_mul_sizet((size_t)size, sizeof(char*), &malloc_size) !=
            OE_OK)
            goto done;

        /* Calculate space for each string */
        for (int i = 0; i < size; i++)
        {
            const uint64_t vaddr = (uint64_t)buffer[i] - enclave->start_address;
            const char* name = elf64_get_function_name(&elf, vaddr);

            if (!name)
                name = unknown;

            if (oe_safe_add_sizet(malloc_size, strlen(name), &malloc_size) !=
                OE_OK)
                goto done;

            if (oe_safe_add_sizet(malloc_size, sizeof(char), &malloc_size) !=
                OE_OK)
                goto done;
        }
    }

    /* Allocate the array of string pointers, followed by the strings */
    ptr = (char*)malloc(malloc_size);
    if (!ptr)
        goto done;

    /* Set pointer to array of strings */
    ret = (char**)ptr;

    /* Skip over array of strings */
    ptr += (size_t)size * sizeof(char*);

    /* Copy strings into return buffer */
    for (int i = 0; i < size; i++)
    {
        const uint64_t vaddr = (uint64_t)buffer[i] - enclave->start_address;
        const char* name = elf64_get_function_name(&elf, vaddr);

        if (!name)
            name = unknown;

        size_t name_size = strlen(name) + sizeof(char);
        oe_memcpy_s(ptr, name_size, name, name_size);
        ret[i] = ptr;
        ptr += name_size;
    }

done:

    if (elf_loaded)
        elf64_unload(&elf);

    return ret;
}

oe_result_t oe_sgx_backtrace_symbols_ocall(
    oe_enclave_t* oe_enclave,
    const uint64_t* buffer,
    size_t size,
    void* symbols_buffer,
    size_t symbols_buffer_size,
    size_t* symbols_buffer_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    char** strings = NULL;

    /* Reject invalid parameters. */
    if (!oe_enclave || !buffer || size > OE_INT_MAX || !symbols_buffer_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert the addresses into symbol strings. */
    strings = _backtrace_symbols(oe_enclave, (void* const*)buffer, (int)size);
    if (!strings)
        OE_RAISE(OE_FAILURE);

    *symbols_buffer_size_out = symbols_buffer_size;

    OE_CHECK(oe_argv_to_buffer(
        (const char**)strings,
        size,
        symbols_buffer,
        symbols_buffer_size,
        symbols_buffer_size_out));

    result = OE_OK;

done:

    if (strings)
        free(strings);

    return result;
}

oe_result_t oe_sgx_log_backtrace_ocall(
    oe_enclave_t* oe_enclave,
    oe_log_level_t level,
    const uint64_t* buffer,
    size_t size)
{
    oe_result_t result = OE_UNEXPECTED;
    char** strings = NULL;

    oe_log(level, "Backtrace:\n");

    /* Reject invalid parameters. */
    if (!oe_enclave || !buffer || size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert the addresses into symbol strings. */
    strings = _backtrace_symbols(oe_enclave, (void* const*)buffer, (int)size);
    if (!strings)
        OE_RAISE(OE_FAILURE);

    for (size_t i = 0; i < size; ++i)
    {
        oe_log(level, "%s(): %p\n", strings[i], buffer[i]);
    }

    result = OE_OK;

done:

    if (strings)
        free(strings);

    return result;
}
