// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hostthread.h"
#include "sgxquoteprovider.h"

/**
 * This file manages the dcap_quoteprov shared library.
 * It loads the library during program startup and keeps it loaded until the
 * application exits. Intel's quoting library repeatedly loads and unloads
 * dcap_quoteprov, but this causes a crash in libssl.so. (See
 * https://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=2325).
 * Keeping dcap_quoteprov pinned in memory solves the libssl.so crash.
 */

extern oe_sgx_quote_provider_t provider;

void oe_quote_provider_log(sgx_ql_log_level_t level, const char* message)
{
    const char* level_string = level == 0 ? "ERROR" : "INFO";
    char formatted[1024];

    snprintf(formatted, sizeof(formatted), "[%s]: %s\n", level_string, message);

    formatted[sizeof(formatted) - 1] = 0;

    OE_TRACE_INFO("dcap_quoteprov: %s", formatted);
}

oe_result_t oe_initialize_quote_provider()
{
    oe_result_t result = OE_OK;
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, oe_load_quote_provider);

    if (!provider.handle)
        OE_RAISE_MSG(
            OE_QUOTE_PROVIDER_LOAD_ERROR,
            "oe_initialize_quote_provider failed",
            NULL);
done:
    return result;
}

oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    sgx_ql_get_revocation_info_params_t params = {0};
    sgx_plat_error_t r = SGX_PLAT_ERROR_OUT_OF_MEMORY;
    sgx_ql_revocation_info_t* revocation_info = NULL;
    uint32_t host_buffer_size = 0;
    uint8_t* p = 0;
    uint8_t* p_end = 0;

    OE_CHECK(oe_initialize_quote_provider());

    if (!provider.get_revocation_info || !provider.free_revocation_info)
        OE_RAISE(OE_QUOTE_PROVIDER_LOAD_ERROR);

    params.version = SGX_QL_REVOCATION_INFO_VERSION_1;
    params.fmspc = args->fmspc;
    params.fmspc_size = sizeof(args->fmspc);
    params.crl_urls = args->crl_urls;
    params.crl_url_count = args->num_crl_urls;

    if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
    {
        // If info tracing is enabled, install the logging function.
        OE_TRACE_INFO("input: fmspc = \n");
        oe_hex_dump(params.fmspc, params.fmspc_size);
        for (uint32_t i = 0; i < params.crl_url_count; ++i)
        {
            OE_TRACE_INFO("input: crl_url[%d] = %s\n", i, params.crl_urls[i]);
        }
    }

    r = provider.get_revocation_info(&params, &revocation_info);

    if (r != SGX_PLAT_ERROR_OK || revocation_info == NULL)
    {
        OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
    }

    if (revocation_info->tcb_info == NULL ||
        revocation_info->tcb_info_size == 0)
    {
        OE_RAISE_MSG(OE_INVALID_REVOCATION_INFO, "tcb_info is NULL", NULL);
    }
    host_buffer_size += revocation_info->tcb_info_size + 1;

    if (revocation_info->tcb_issuer_chain == NULL ||
        revocation_info->tcb_issuer_chain_size == 0)
    {
        OE_RAISE_MSG(
            OE_INVALID_REVOCATION_INFO, "tcb_issuer_chain is NULL", NULL);
    }
    host_buffer_size += revocation_info->tcb_issuer_chain_size + 1;

    if (revocation_info->crl_count != args->num_crl_urls)
    {
        OE_RAISE_MSG(
            OE_INVALID_REVOCATION_INFO,
            "crl_count mismatch: %d != %d",
            revocation_info->crl_count,
            args->num_crl_urls);
    }

    for (uint32_t i = 0; i < revocation_info->crl_count; ++i)
    {
        if (revocation_info->crls[i].crl_data == NULL ||
            revocation_info->crls[i].crl_data_size == 0)
        {
            OE_RAISE_MSG(
                OE_INVALID_REVOCATION_INFO, "crl[%d].crl_data is NULL.", i);
        }
        OE_TRACE_VERBOSE(
            "crl_data = \n[%s]\n", revocation_info->crls[i].crl_data);
        // CRL is in DER format. Null not added.
        host_buffer_size += revocation_info->crls[i].crl_data_size;

        if (revocation_info->crls[i].crl_issuer_chain == NULL ||
            revocation_info->crls[i].crl_issuer_chain_size == 0)
        {
            OE_RAISE_MSG(
                OE_INVALID_REVOCATION_INFO,
                "crl[%d].crl_issuer_chain is NULL.",
                i);
        }
        host_buffer_size += revocation_info->crls[i].crl_issuer_chain_size + 1;
    }

    p = (uint8_t*)calloc(1, host_buffer_size);
    p_end = p + host_buffer_size;
    if (p == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    args->buffer = p;

    if (revocation_info->tcb_info != NULL)
    {
        args->tcb_info = p;
        args->tcb_info_size = revocation_info->tcb_info_size;
        OE_CHECK(oe_memcpy_s(
            args->tcb_info,
            args->tcb_info_size,
            revocation_info->tcb_info,
            revocation_info->tcb_info_size));
        // Add null terminator
        args->tcb_info[args->tcb_info_size++] = 0;
        p += args->tcb_info_size;
        OE_TRACE_INFO("tcb_info_size = %d\n", revocation_info->tcb_info_size);
        OE_TRACE_INFO("tcb_info json = \n%s\n", args->tcb_info);
    }

    if (revocation_info->tcb_issuer_chain != NULL)
    {
        args->tcb_issuer_chain = p;
        args->tcb_issuer_chain_size = revocation_info->tcb_issuer_chain_size;
        OE_CHECK(oe_memcpy_s(
            args->tcb_issuer_chain,
            args->tcb_issuer_chain_size,
            revocation_info->tcb_issuer_chain,
            revocation_info->tcb_issuer_chain_size));
        // Add null terminator
        args->tcb_issuer_chain[args->tcb_issuer_chain_size++] = 0;
        p += args->tcb_issuer_chain_size;
        OE_TRACE_INFO(
            "tcb_issuer_chain_size = %d\n",
            revocation_info->tcb_issuer_chain_size);
    }

    for (uint32_t i = 0; i < revocation_info->crl_count; ++i)
    {
        if (revocation_info->crls[i].crl_data != NULL)
        {
            args->crl[i] = p;
            args->crl_size[i] = revocation_info->crls[i].crl_data_size;
            OE_CHECK(oe_memcpy_s(
                args->crl[i],
                args->crl_size[i],
                revocation_info->crls[i].crl_data,
                revocation_info->crls[i].crl_data_size));
            // CRL is in DER format. Null not added.
            p += args->crl_size[i];
            OE_TRACE_INFO(
                "crls[%d].crl_data_size = %d\n",
                i,
                revocation_info->crls[i].crl_data_size);
        }
        if (revocation_info->crls[i].crl_issuer_chain != NULL)
        {
            args->crl_issuer_chain[i] = p;
            args->crl_issuer_chain_size[i] =
                revocation_info->crls[i].crl_issuer_chain_size;
            OE_CHECK(oe_memcpy_s(
                args->crl_issuer_chain[i],
                args->crl_issuer_chain_size[i],
                revocation_info->crls[i].crl_issuer_chain,
                revocation_info->crls[i].crl_issuer_chain_size));
            // Add null terminator
            args->crl_issuer_chain[i][args->crl_issuer_chain_size[i]++] = 0;
            p += args->crl_issuer_chain_size[i];
            OE_TRACE_INFO(
                "crls[%d].crl_issuer_chain_size = %d\n",
                i,
                revocation_info->crls[i].crl_issuer_chain_size);
            OE_TRACE_INFO(
                "crls[%d].crl_issuer_chain = \n%*.*s\n",
                i,
                revocation_info->crls[i].crl_issuer_chain_size,
                revocation_info->crls[i].crl_issuer_chain_size,
                revocation_info->crls[i].crl_issuer_chain);
        }
    }

    if (p != p_end)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:
    if (revocation_info != NULL)
        provider.free_revocation_info(revocation_info);

    return result;
}

void oe_free_get_revocation_info_args(oe_get_revocation_info_args_t* args)
{
    if (args)
    {
        if (args->buffer)
            free(args->buffer);
    }
}

oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    sgx_plat_error_t r = SGX_PLAT_ERROR_OUT_OF_MEMORY;
    sgx_qe_identity_info_t* identity = NULL;
    uint32_t host_buffer_size = 0;
    uint8_t* p = 0;
    uint8_t* p_end = 0;
    OE_TRACE_INFO("Calling %s\n", __FUNCTION__);

    OE_CHECK(oe_initialize_quote_provider());

    if (!provider.get_qe_identity_info || !provider.free_qe_identity_info)
    {
        OE_TRACE_WARNING(
            "Warning: QE Identity was not supported by quote provider\n");
        result = OE_QUOTE_PROVIDER_CALL_ERROR;
        goto done;
    }

    // fetch qe identity information
    r = provider.get_qe_identity_info(&identity);
    if (r != SGX_PLAT_ERROR_OK || identity == NULL)
    {
        OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
    }

    if (identity->qe_id_info == NULL || identity->qe_id_info_size == 0)
    {
        OE_TRACE_ERROR("qe_id_info is NULL.\n");
        OE_RAISE(OE_INVALID_QE_IDENTITY_INFO);
    }
    host_buffer_size += identity->qe_id_info_size + 1;

    if (identity->issuer_chain == NULL || identity->issuer_chain_size == 0)
        OE_RAISE_MSG(OE_INVALID_QE_IDENTITY_INFO, "issuer_chain is NULL", NULL);

    host_buffer_size += identity->issuer_chain_size + 1;
    p = (uint8_t*)calloc(1, host_buffer_size);
    p_end = p + host_buffer_size;
    if (p == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    args->host_out_buffer = p;

    if (identity->qe_id_info != NULL)
    {
        args->qe_id_info = p;
        args->qe_id_info_size = identity->qe_id_info_size;
        OE_CHECK(oe_memcpy_s(
            args->qe_id_info,
            args->qe_id_info_size,
            identity->qe_id_info,
            identity->qe_id_info_size));
        // Add null terminator
        args->qe_id_info[args->qe_id_info_size++] = 0;
        p += args->qe_id_info_size;
        OE_TRACE_INFO("qe_id_info_size = %ld\n", args->qe_id_info_size);
        OE_TRACE_INFO("qe_id_info json = \n%s\n", args->qe_id_info);
    }

    if (identity->issuer_chain != NULL)
    {
        args->issuer_chain = p;
        args->issuer_chain_size = identity->issuer_chain_size;
        OE_CHECK(oe_memcpy_s(
            args->issuer_chain,
            args->issuer_chain_size,
            identity->issuer_chain,
            identity->issuer_chain_size));
        // Add null terminator
        args->issuer_chain[args->issuer_chain_size++] = 0;
        p += args->issuer_chain_size;
        OE_TRACE_INFO("issuer_chain_size = %ld\n", args->issuer_chain_size);
    }

    if (p != p_end)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;
done:
    if (identity != NULL)
    {
        provider.free_qe_identity_info(identity);
    }
    return result;
}

void oe_free_qe_identity_info_args(oe_get_qe_identity_info_args_t* args)
{
    if (args)
    {
        if (args->host_out_buffer)
            free(args->host_out_buffer);
    }
}
