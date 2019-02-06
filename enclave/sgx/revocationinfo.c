// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/elibc/stdlib.h>
#include <openenclave/elibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include "../common/sgx/revocation.h"

/**
 * Validate and copy buffer to enclave memory.
 */
static oe_result_t _copy_buffer_to_enclave(
    uint8_t** dst,
    size_t* dst_size,
    const uint8_t* src,
    size_t src_size)
{
    oe_result_t result = OE_FAILURE;
    if (!src || src_size == 0 || !oe_is_outside_enclave(src, src_size) ||
        dst == NULL || dst_size == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    *dst = oe_malloc(src_size);
    if (*dst == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(oe_memcpy_s(*dst, src_size, src, src_size));
    *dst_size = src_size;
    result = OE_OK;

done:
    return result;
}

/**
 * Call into host to fetch revocation information.
 */
oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    size_t host_args_buffer_size = sizeof(*args);
    uint8_t* host_args_buffer = NULL;
    oe_get_revocation_info_args_t* host_args = NULL;
    oe_get_revocation_info_args_t tmp_args = {0};
    uint8_t* p = NULL;
    size_t crl_url_sizes[2] = {0};

    if (args == NULL || args->num_crl_urls != 2 || args->crl_urls[0] == NULL ||
        args->crl_urls[1] == NULL)
        OE_RAISE(OE_FAILURE);

    // Compute size of buffer to allocate in host memory to marshal the
    // arguments.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        result = oe_safe_add_sizet(
            oe_strlen(args->crl_urls[i]), 1, &crl_url_sizes[i]);
        if (result != OE_OK)
            goto done;

        result = oe_safe_add_sizet(
            host_args_buffer_size, crl_url_sizes[i], &host_args_buffer_size);

        if (result != OE_OK)
            goto done;
    }

    host_args_buffer = oe_host_malloc(host_args_buffer_size);
    if (host_args_buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    p = host_args_buffer;
    host_args = (oe_get_revocation_info_args_t*)p;
    *host_args = *args;
    p += sizeof(*host_args);

    // Copy input buffers.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        host_args->crl_urls[i] = (const char*)p;
        OE_CHECK(oe_memcpy_s(
            p, crl_url_sizes[i], args->crl_urls[i], crl_url_sizes[i]));
        p += crl_url_sizes[i];
    }

    OE_CHECK(oe_ocall(OE_OCALL_GET_REVOCATION_INFO, (uint64_t)host_args, NULL));

    // Copy args to prevent TOCTOU issues.
    tmp_args = *host_args;

    OE_CHECK(tmp_args.result);

    if (tmp_args.host_out_buffer == NULL ||
        !oe_is_outside_enclave(tmp_args.host_out_buffer, sizeof(uint8_t)))
        OE_RAISE(OE_UNEXPECTED);

    // Ensure that all required outputs exist.
    OE_CHECK(_copy_buffer_to_enclave(
        &args->tcb_info,
        &args->tcb_info_size,
        tmp_args.tcb_info,
        tmp_args.tcb_info_size));
    OE_CHECK(_copy_buffer_to_enclave(
        &args->tcb_issuer_chain,
        &args->tcb_issuer_chain_size,
        tmp_args.tcb_issuer_chain,
        tmp_args.tcb_issuer_chain_size));

    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        OE_CHECK(_copy_buffer_to_enclave(
            &args->crl[i],
            &args->crl_size[i],
            tmp_args.crl[i],
            tmp_args.crl_size[i]));
        OE_CHECK(_copy_buffer_to_enclave(
            &args->crl_issuer_chain[i],
            &args->crl_issuer_chain_size[i],
            tmp_args.crl_issuer_chain[i],
            tmp_args.crl_issuer_chain_size[i]));
    }

    // Check for null terminators.
    if (args->tcb_info[args->tcb_info_size - 1] != 0 ||
        args->tcb_issuer_chain[args->tcb_issuer_chain_size - 1] != 0)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        if (args->crl_issuer_chain[i][args->crl_issuer_chain_size[i] - 1] != 0)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    result = OE_OK;
done:
    // Free args buffer and buffer allocated by host.
    if (host_args_buffer)
        oe_host_free(host_args_buffer);

    return result;
}

void oe_cleanup_get_revocation_info_args(oe_get_revocation_info_args_t* args)
{
    if (!args)
        return;

    // Free buffers on the enclave side.
    for (int32_t i = (int32_t)(args->num_crl_urls - 1); i >= 0; --i)
    {
        oe_free(args->crl_issuer_chain[i]);
        oe_free(args->crl[i]);
    }
    oe_free(args->tcb_issuer_chain);
    oe_free(args->tcb_info);

    if (args->host_out_buffer)
        oe_host_free(args->host_out_buffer);
}
