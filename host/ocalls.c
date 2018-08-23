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

#include <openenclave/host.h>

#include <openenclave/internal/backtrace_symbols.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include "enclave.h"
#include "ocalls.h"
#include "quote.h"
#include "sgxquoteprovider.h"

void HandleMalloc(uint64_t argIn, uint64_t* argOut)
{
    if (argOut)
        *argOut = (uint64_t)malloc(argIn);
}

void HandleRealloc(uint64_t argIn, uint64_t* argOut)
{
    oe_realloc_args_t* args = (oe_realloc_args_t*)argIn;

    if (args)
    {
        if (argOut)
            *argOut = (uint64_t)realloc(args->ptr, args->size);
    }
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void HandlePuts(uint64_t argIn)
{
    const char* str = (const char*)argIn;

    if (str)
        puts(str);
}

void HandlePrint(uint64_t argIn)
{
    oe_print_args_t* args = (oe_print_args_t*)argIn;

    if (args)
    {
        if (args->device == 0)
        {
            fprintf(stdout, "%s", args->str);
            fflush(stdout);
        }
        else if (args->device == 1)
        {
            fprintf(stderr, "%s", args->str);
            fflush(stderr);
        }
    }
}

void HandlePutchar(uint64_t argIn)
{
    int c = (int)argIn;
    putchar(c);
}

void HandleThreadWait(oe_enclave_t* enclave, uint64_t argIn)
{
    const uint64_t tcs = argIn;
    EnclaveEvent* event = GetEnclaveEvent(enclave, tcs);
    assert(event);

#if defined(__linux__)

    if (__sync_fetch_and_add(&event->value, -1) == 0)
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
        } while (event->value == -1);
    }

#elif defined(_WIN32)

    WaitForSingleObject(event->handle, INFINITE);

#endif
}

void HandleThreadWake(oe_enclave_t* enclave, uint64_t argIn)
{
    const uint64_t tcs = argIn;
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

void HandleThreadWakeWait(oe_enclave_t* enclave, uint64_t argIn)
{
    oe_thread_wake_wait_args_t* args = (oe_thread_wake_wait_args_t*)argIn;

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

void HandleGetQuote(uint64_t argIn)
{
    oe_get_quote_args_t* args = (oe_get_quote_args_t*)argIn;
    if (!args)
        return;

    args->result =
        sgx_get_quote(&args->sgxReport, args->quote, &args->quoteSize);
}

#ifdef OE_USE_LIBSGX

void HandleGetQuoteRevocationInfo(uint64_t argIn)
{
    oe_get_revocation_info_args_t* args = (oe_get_revocation_info_args_t*)argIn;
    if (!args)
        return;

    args->result = oe_get_revocation_info(args);
}

#endif

void HandleGetQETargetInfo(uint64_t argIn)
{
    oe_get_qetarget_info_args_t* args = (oe_get_qetarget_info_args_t*)argIn;
    if (!args)
        return;

    args->result = sgx_get_qetarget_info(&args->targetInfo);
}

#if defined(OE_USE_DEBUG_MALLOC)
void handle_malloc_dump(oe_enclave_t* enclave, uint64_t arg)
{
    oe_malloc_dump_args_t* args = (oe_malloc_dump_args_t*)arg;
    char** syms = NULL;

    if (!args)
        goto done;

    if (!(syms = oe_backtrace_symbols(enclave, args->addrs, args->num_addrs)))
        goto done;

    printf("%llu bytes\n", OE_LLX(args->size));

    for (size_t i = 0; i < args->num_addrs; i++)
        printf("%s(): %p\n", syms[i], args->addrs[i]);

    printf("\n");

done:

    if (syms)
        free(syms);
}
#endif
