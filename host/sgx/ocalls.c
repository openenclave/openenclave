// Copyright (c) Open Enclave SDK contributors.
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
#include <openenclave/internal/argv.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../ocalls.h"
#include "enclave.h"
#include "ocalls.h"
#include "platform_u.h"
#include "quote.h"
#include "sgxquoteprovider.h"

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

void oe_sgx_thread_wake_wait_ocall(
    oe_enclave_t* enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs)
{
    if (!waiter_tcs || !self_tcs)
        return;

    HandleThreadWake(enclave, waiter_tcs);
    HandleThreadWait(enclave, self_tcs);
}

oe_result_t oe_get_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out)
{
    oe_result_t result;

    result = sgx_get_quote(
        format_id, opt_params, opt_params_size, sgx_report, quote, &quote_size);

    if (quote_size_out)
        *quote_size_out = quote_size;

    return result;
}

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

oe_result_t oe_get_quote_verification_collateral_ocall(
    uint8_t fmspc[6],
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_get_sgx_quote_verification_collateral_args_t args = {0};
    bool buffer_too_small = false;

    /* fmspc */
    memcpy(args.fmspc, fmspc, sizeof(args.fmspc));

    /* Populate the output fields. */
    OE_CHECK(oe_get_sgx_quote_verification_collateral(&args));

    OE_CHECK(_copy_output_buffer(
        tcb_info,
        tcb_info_size,
        tcb_info_size_out,
        args.tcb_info,
        args.tcb_info_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        tcb_info_issuer_chain,
        tcb_info_issuer_chain_size,
        tcb_info_issuer_chain_size_out,
        args.tcb_info_issuer_chain,
        args.tcb_info_issuer_chain_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        pck_crl,
        pck_crl_size,
        pck_crl_size_out,
        args.pck_crl,
        args.pck_crl_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        root_ca_crl,
        root_ca_crl_size,
        root_ca_crl_size_out,
        args.root_ca_crl,
        args.root_ca_crl_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        pck_crl_issuer_chain,
        pck_crl_issuer_chain_size,
        pck_crl_issuer_chain_size_out,
        args.pck_crl_issuer_chain,
        args.pck_crl_issuer_chain_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        qe_identity,
        qe_identity_size,
        qe_identity_size_out,
        args.qe_identity,
        args.qe_identity_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    OE_CHECK(_copy_output_buffer(
        qe_identity_issuer_chain,
        qe_identity_issuer_chain_size,
        qe_identity_issuer_chain_size_out,
        args.qe_identity_issuer_chain,
        args.qe_identity_issuer_chain_size,
        &buffer_too_small));

    if (buffer_too_small)
        OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);

    result = OE_OK;

done:

    free(args.host_out_buffer);

    return result;
}

oe_result_t oe_get_qetarget_info_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info)
{
    return sgx_get_qetarget_info(
        format_id, opt_params, opt_params_size, target_info);
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

oe_result_t oe_get_supported_attester_format_ids_ocall(
    void* format_ids,
    size_t format_ids_size,
    size_t* format_ids_size_out)
{
    oe_result_t result;

    result =
        sgx_get_supported_attester_format_ids(format_ids, &format_ids_size);

    if (format_ids_size_out)
        *format_ids_size_out = format_ids_size;

    return result;
}
