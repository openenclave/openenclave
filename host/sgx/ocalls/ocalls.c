// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#elif defined(_WIN32)
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#include <ntstatus.h>
#endif

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../enclave.h"
#include "../quote.h"
#include "../sgxquoteprovider.h"
#include "ocalls.h"
#include "platform_u.h"

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
    uint8_t collateral_provider,
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
    return oe_get_quote_verification_collateral_with_baseline_ocall(
        fmspc,
        collateral_provider,
        NULL,
        0,
        tcb_info,
        tcb_info_size,
        tcb_info_size_out,
        tcb_info_issuer_chain,
        tcb_info_issuer_chain_size,
        tcb_info_issuer_chain_size_out,
        pck_crl,
        pck_crl_size,
        pck_crl_size_out,
        root_ca_crl,
        root_ca_crl_size,
        root_ca_crl_size_out,
        pck_crl_issuer_chain,
        pck_crl_issuer_chain_size,
        pck_crl_issuer_chain_size_out,
        qe_identity,
        qe_identity_size,
        qe_identity_size_out,
        qe_identity_issuer_chain,
        qe_identity_issuer_chain_size,
        qe_identity_issuer_chain_size_out);
}

oe_result_t oe_get_quote_verification_collateral_with_baseline_ocall(
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* baseline,
    size_t baseline_size,
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

    /* The value of any_buffer_too_small will be true if any buffer_too_small
     * value becomes true. It is used to prevent terminating the collateral
     * initialization process early. */
    bool any_buffer_too_small = false;

    /* fmspc */
    memcpy(args.fmspc, fmspc, sizeof(args.fmspc));

    /* collateral_provider */
    args.collateral_provider = collateral_provider;

    /* baseline */
    args.baseline = baseline;

    /* baseline_size */
    args.baseline_size = baseline_size;

    /* Populate the output fields. */
    OE_CHECK(oe_get_sgx_quote_verification_collateral(&args));

    OE_CHECK(_copy_output_buffer(
        tcb_info,
        tcb_info_size,
        tcb_info_size_out,
        args.tcb_info,
        args.tcb_info_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        tcb_info_issuer_chain,
        tcb_info_issuer_chain_size,
        tcb_info_issuer_chain_size_out,
        args.tcb_info_issuer_chain,
        args.tcb_info_issuer_chain_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        pck_crl,
        pck_crl_size,
        pck_crl_size_out,
        args.pck_crl,
        args.pck_crl_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        root_ca_crl,
        root_ca_crl_size,
        root_ca_crl_size_out,
        args.root_ca_crl,
        args.root_ca_crl_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        pck_crl_issuer_chain,
        pck_crl_issuer_chain_size,
        pck_crl_issuer_chain_size_out,
        args.pck_crl_issuer_chain,
        args.pck_crl_issuer_chain_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        qe_identity,
        qe_identity_size,
        qe_identity_size_out,
        args.qe_identity,
        args.qe_identity_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    OE_CHECK(_copy_output_buffer(
        qe_identity_issuer_chain,
        qe_identity_issuer_chain_size,
        qe_identity_issuer_chain_size_out,
        args.qe_identity_issuer_chain,
        args.qe_identity_issuer_chain_size,
        &buffer_too_small));

    any_buffer_too_small |= buffer_too_small;

    if (any_buffer_too_small)
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

oe_result_t oe_get_supported_attester_format_ids_ocall(format_ids_t* format_ids)
{
    return sgx_get_supported_attester_format_ids(
        &format_ids->data, &format_ids->size);
}

oe_result_t oe_verify_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size)
{
    oe_result_t result;

    result = sgx_verify_quote(
        format_id,
        opt_params,
        opt_params_size,
        p_quote,
        quote_size,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        qve_report_size,
        p_supplemental_data,
        supplemental_data_size,
        p_supplemental_data_size_out,
        collateral_version,
        p_tcb_info,
        tcb_info_size,
        p_tcb_info_issuer_chain,
        tcb_info_issuer_chain_size,
        p_pck_crl,
        pck_crl_size,
        p_root_ca_crl,
        root_ca_crl_size,
        p_pck_crl_issuer_chain,
        pck_crl_issuer_chain_size,
        p_qe_identity,
        qe_identity_size,
        p_qe_identity_issuer_chain,
        qe_identity_issuer_chain_size);

    return result;
}

oe_result_t oe_sgx_get_additional_host_entropy_ocall(uint8_t* data, size_t size)
{
    oe_result_t result = OE_FAILURE;

    if (!data || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(__linux__)
    /* Fail on either the function returns error (-1) or the buffer is partially
     * filled */
    if (getrandom((void*)data, size, 0) < (ssize_t)size)
        goto done;
#elif defined(_WIN32)
    if (BCryptGenRandom(
            NULL, data, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) !=
        STATUS_SUCCESS)
        goto done;
#endif

    result = OE_OK;

done:
    return result;
}
