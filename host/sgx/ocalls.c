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
#include <openenclave/internal/argv.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../ocalls.h"
#include "enclave.h"
#include "internal_u.h"
#include "quote.h"
#include "sgxquoteprovider.h"

void* oe_realloc_ocall(void* ptr, size_t size)
{
    return realloc(ptr, size);
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

void oe_thread_wake_wait_ocall(
    oe_enclave_t* enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs)
{
    if (!waiter_tcs || !self_tcs)
        return;

#if defined(__linux__)
    HandleThreadWake(enclave, waiter_tcs);
    HandleThreadWait(enclave, self_tcs);
#elif defined(_WIN32)
    HandleThreadWake(enclave, waiter_tcs);
    HandleThreadWait(enclave, self_tcs);
#endif
}

oe_result_t oe_get_quote_ocall(
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out)
{
    oe_result_t result;

    result = sgx_get_quote(sgx_report, quote, &quote_size);

    if (quote_size_out)
        *quote_size_out = quote_size;

    return result;
}

#if defined(OE_USE_LIBSGX)

/* Copy the source array to an output buffer. */
static oe_result_t _copy_output_buffer(
    void* dest,
    size_t dest_size,
    size_t* dest_size_out,
    const void* src,
    size_t src_size,
    bool* buffer_too_small)
{
    oe_result_t result = OE_UNEXPECTED;

    if ((dest_size && !dest) || !dest_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    *dest_size_out = src_size;

    if (dest_size < src_size)
        *buffer_too_small = true;
    else
        memcpy(dest, src, src_size);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_revocation_info_ocall(
    uint8_t fmspc[6],
    size_t num_crl_urls,
    const char* crl_urls0,
    const char* crl_urls1,
    const char* crl_urls2,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_issuer_chain,
    size_t tcb_issuer_chain_size,
    size_t* tcb_issuer_chain_size_out,
    void* crl0,
    size_t crl0_size,
    size_t* crl0_size_out,
    void* crl1,
    size_t crl1_size,
    size_t* crl1_size_out,
    void* crl2,
    size_t crl2_size,
    size_t* crl2_size_out,
    void* crl_issuer_chain0,
    size_t crl_issuer_chain0_size,
    size_t* crl_issuer_chain0_size_out,
    void* crl_issuer_chain1,
    size_t crl_issuer_chain1_size,
    size_t* crl_issuer_chain1_size_out,
    void* crl_issuer_chain2,
    size_t crl_issuer_chain2_size,
    size_t* crl_issuer_chain2_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_revocation_info_args_t args = {0};
    bool buffer_too_small = false;

    /* fmspc */
    memcpy(args.fmspc, fmspc, sizeof(args.fmspc));

    /* crl_urls */
    args.num_crl_urls = (uint32_t)num_crl_urls;
    args.crl_urls[0] = crl_urls0;
    args.crl_urls[1] = crl_urls1;
    args.crl_urls[2] = crl_urls2;

    /* Populate the output fields. */
    OE_CHECK(oe_get_revocation_info(&args));

    OE_CHECK(_copy_output_buffer(
        tcb_info,
        tcb_info_size,
        tcb_info_size_out,
        args.tcb_info,
        args.tcb_info_size,
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        tcb_issuer_chain,
        tcb_issuer_chain_size,
        tcb_issuer_chain_size_out,
        args.tcb_issuer_chain,
        args.tcb_issuer_chain_size,
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl0,
        crl0_size,
        crl0_size_out,
        args.crl[0],
        args.crl_size[0],
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl1,
        crl1_size,
        crl1_size_out,
        args.crl[1],
        args.crl_size[1],
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl2,
        crl2_size,
        crl2_size_out,
        args.crl[2],
        args.crl_size[2],
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl_issuer_chain0,
        crl_issuer_chain0_size,
        crl_issuer_chain0_size_out,
        args.crl_issuer_chain[0],
        args.crl_issuer_chain_size[0],
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl_issuer_chain1,
        crl_issuer_chain1_size,
        crl_issuer_chain1_size_out,
        args.crl_issuer_chain[1],
        args.crl_issuer_chain_size[1],
        &buffer_too_small));

    OE_CHECK(_copy_output_buffer(
        crl_issuer_chain2,
        crl_issuer_chain2_size,
        crl_issuer_chain2_size_out,
        args.crl_issuer_chain[2],
        args.crl_issuer_chain_size[2],
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    result = OE_OK;

done:

    free(args.buffer);

    return result;
}

oe_result_t oe_get_qe_identify_info_ocall(
    void* qe_id_info,
    size_t qe_id_info_size,
    size_t* qe_id_info_size_out,
    void* issuer_chain,
    size_t issuer_chain_size,
    size_t* issuer_chain_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_qe_identity_info_args_t args = {0};

    if (!qe_id_info_size_out || !issuer_chain_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_get_qe_identity_info(&args));

    if (args.qe_id_info_size > qe_id_info_size)
    {
        *qe_id_info_size_out = args.qe_id_info_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    if (args.issuer_chain_size > issuer_chain_size)
    {
        *issuer_chain_size_out = args.issuer_chain_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    if (qe_id_info)
        memcpy(qe_id_info, args.qe_id_info, args.qe_id_info_size);

    *qe_id_info_size_out = args.qe_id_info_size;

    if (issuer_chain)
        memcpy(issuer_chain, args.issuer_chain, args.issuer_chain_size);

    *issuer_chain_size_out = args.issuer_chain_size;

done:

    if (args.host_out_buffer)
        free(args.host_out_buffer);

    return result;
}

#else /* !defined(OE_USE_LIBSGX) */

oe_result_t oe_get_revocation_info_ocall(
    uint8_t fmspc[6],
    size_t num_crl_urls,
    const char* crl_urls0,
    const char* crl_urls1,
    const char* crl_urls2,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_issuer_chain,
    size_t tcb_issuer_chain_size,
    size_t* tcb_issuer_chain_size_out,
    void* crl0,
    size_t crl0_size,
    size_t* crl0_size_out,
    void* crl1,
    size_t crl1_size,
    size_t* crl1_size_out,
    void* crl2,
    size_t crl2_size,
    size_t* crl2_size_out,
    void* crl_issuer_chain0,
    size_t crl_issuer_chain0_size,
    size_t* crl_issuer_chain0_size_out,
    void* crl_issuer_chain1,
    size_t crl_issuer_chain1_size,
    size_t* crl_issuer_chain1_size_out,
    void* crl_issuer_chain2,
    size_t crl_issuer_chain2_size,
    size_t* crl_issuer_chain2_size_out)
{
    OE_UNUSED(fmspc);
    OE_UNUSED(num_crl_urls);
    OE_UNUSED(crl_urls0);
    OE_UNUSED(crl_urls1);
    OE_UNUSED(crl_urls2);
    OE_UNUSED(tcb_info);
    OE_UNUSED(tcb_info_size);
    OE_UNUSED(tcb_info_size_out);
    OE_UNUSED(tcb_issuer_chain);
    OE_UNUSED(tcb_issuer_chain_size);
    OE_UNUSED(tcb_issuer_chain_size_out);
    OE_UNUSED(crl0);
    OE_UNUSED(crl0_size);
    OE_UNUSED(crl0_size_out);
    OE_UNUSED(crl1);
    OE_UNUSED(crl1_size);
    OE_UNUSED(crl1_size_out);
    OE_UNUSED(crl2);
    OE_UNUSED(crl2_size);
    OE_UNUSED(crl2_size_out);
    OE_UNUSED(crl_issuer_chain0);
    OE_UNUSED(crl_issuer_chain0_size);
    OE_UNUSED(crl_issuer_chain0_size_out);
    OE_UNUSED(crl_issuer_chain1);
    OE_UNUSED(crl_issuer_chain1_size);
    OE_UNUSED(crl_issuer_chain1_size_out);
    OE_UNUSED(crl_issuer_chain2);
    OE_UNUSED(crl_issuer_chain2_size);
    OE_UNUSED(crl_issuer_chain2_size_out);

    return OE_UNSUPPORTED;
}

oe_result_t oe_get_qe_identify_info_ocall(
    void* qe_id_info,
    size_t qe_id_info_size,
    size_t* qe_id_info_size_out,
    void* issuer_chain,
    size_t issuer_chain_size,
    size_t* issuer_chain_size_out)
{
    OE_UNUSED(qe_id_info);
    OE_UNUSED(qe_id_info_size);
    OE_UNUSED(qe_id_info_size_out);
    OE_UNUSED(issuer_chain);
    OE_UNUSED(issuer_chain_size);
    OE_UNUSED(issuer_chain_size_out);

    return OE_UNSUPPORTED;
}

#endif /* !defined(OE_USE_LIBSGX) */

oe_result_t oe_get_qetarget_info_ocall(sgx_target_info_t* target_info)
{
    return sgx_get_qetarget_info(target_info);
}

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

    return ret;
}

oe_result_t oe_backtrace_symbols_ocall(
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
    if (!(strings =
              _backtrace_symbols(oe_enclave, (void* const*)buffer, (int)size)))
    {
        OE_RAISE(OE_FAILURE);
    }

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

void oe_log_ocall(uint32_t log_level, const char* message)
{
    oe_log_message(true, (oe_log_level_t)log_level, message);
}

void oe_write_ocall(int device, const char* str, size_t maxlen)
{
    if (str && (device == 0 || device == 1))
    {
        FILE* stream = (device == 0) ? stdout : stderr;
        size_t len = strnlen(str, maxlen);
        fprintf(stream, "%.*s", (int)len, str);
        fflush(stream);
    }
}
