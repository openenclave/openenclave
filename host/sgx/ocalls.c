// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "enclave.h"
#include "ocalls.h"
#include "quote.h"
#include "sgxquoteprovider.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void HandleRealloc(uint64_t arg_in, uint64_t* arg_out)
{
    oe_realloc_args_t* args = (oe_realloc_args_t*)arg_in;

    if (args)
    {
        if (arg_out)
            *arg_out = (uint64_t)realloc(args->ptr, args->size);
    }
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg_in)
{
    const uint64_t tcs = arg_in;
    EnclaveEvent* event = GetEnclaveEvent(enclave, tcs);
    assert(event);

#if defined(__linux__)

    if (__sync_fetch_and_add(&event->value, (uint32_t)-1) == 0)
    {
        do
        {
            syscall(
                __NR_futex,
                &event->value,
                FUTEX_WAIT_PRIVATE,
                -1,
                NULL,
                NULL,
                0);
            // If event->value is still -1, then this is a spurious-wake.
            // Spurious-wakes are ignored by going back to FUTEX_WAIT.
            // Since FUTEX_WAIT uses atomic instructions to load event->value,
            // it is safe to use a non-atomic operation here.
        } while (event->value == (uint32_t)-1);
    }

#elif defined(_WIN32)

    WaitForSingleObject(event->handle, INFINITE);

#endif
}

void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg_in)
{
    const uint64_t tcs = arg_in;
    EnclaveEvent* event = GetEnclaveEvent(enclave, tcs);
    assert(event);

#if defined(__linux__)

    if (__sync_fetch_and_add(&event->value, 1) != 0)
        syscall(
            __NR_futex, &event->value, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);

#elif defined(_WIN32)

    SetEvent(event->handle);

#endif
}

void HandleThreadWakeWait(oe_enclave_t* enclave, uint64_t arg_in)
{
    oe_thread_wake_wait_args_t* args = (oe_thread_wake_wait_args_t*)arg_in;

    if (!args)
        return;

#if defined(__linux__)

    HandleThreadWake(enclave, (uint64_t)args->waiter_tcs);
    HandleThreadWait(enclave, (uint64_t)args->self_tcs);

#elif defined(_WIN32)

    HandleThreadWake(enclave, (uint64_t)args->waiter_tcs);
    HandleThreadWait(enclave, (uint64_t)args->self_tcs);

#endif
}

void HandleGetQuote(uint64_t arg_in)
{
    oe_get_quote_args_t* args = (oe_get_quote_args_t*)arg_in;
    if (!args)
        return;

    args->result =
        sgx_get_quote(&args->sgx_report, args->quote, &args->quote_size);
}

#ifdef OE_USE_LIBSGX

void HandleGetQuoteRevocationInfo(uint64_t arg_in)
{
    oe_get_revocation_info_args_t* args =
        (oe_get_revocation_info_args_t*)arg_in;
    if (!args)
        return;

    args->result = oe_get_revocation_info(args);
}

void HandleGetQuoteEnclaveIdentityInfo(uint64_t arg_in)
{
    oe_get_qe_identity_info_args_t* args =
        (oe_get_qe_identity_info_args_t*)arg_in;
    if (!args)
        return;

    args->result = oe_get_qe_identity_info(args);
}

#endif

void HandleGetQETargetInfo(uint64_t arg_in)
{
    oe_get_qetarget_info_args_t* args = (oe_get_qetarget_info_args_t*)arg_in;
    if (!args)
        return;

    args->result = sgx_get_qetarget_info(&args->target_info);
}

static char** _backtrace_symbols(
    oe_enclave_t* enclave,
    void* const* buffer,
    int size)
{
    char** ret = NULL;

#if defined(__linux__)

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
            const uint64_t vaddr = (uint64_t)buffer[i] - enclave->addr;
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
    if (!(ptr = (char*)malloc(malloc_size)))
        goto done;

    /* Set pointer to array of strings */
    ret = (char**)ptr;

    /* Skip over array of strings */
    ptr += (size_t)size * sizeof(char*);

    /* Copy strings into return buffer */
    for (int i = 0; i < size; i++)
    {
        const uint64_t vaddr = (uint64_t)buffer[i] - enclave->addr;
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

#endif /* defined(__linux__) */

    return ret;
}

void oe_handle_backtrace_symbols(oe_enclave_t* enclave, uint64_t arg)
{
    oe_backtrace_symbols_args_t* args = (oe_backtrace_symbols_args_t*)arg;

    if (args)
    {
        args->ret = _backtrace_symbols(enclave, args->buffer, args->size);
    }
}

void oe_handle_log(oe_enclave_t* enclave, uint64_t arg)
{
    oe_log_args_t* args = (oe_log_args_t*)arg;
    OE_UNUSED(enclave);
    if (args)
    {
        log_message(true, args);
    }
}
