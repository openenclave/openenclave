// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Uncomment this line to enable tracing.
//#define OE_TRACE_LEVEL 2

#include <dlfcn.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hostthread.h"
#include "platformquoteprovider.h"
#include "sgxquoteprovider.h"

/**
 * This file manages the libngsa_quoteprov.so shared library.
 * It loads the .so during program startup and keeps it loaded till application
 * exit. Intel's quoting library repeatedly loads and unloads
 * libngsa_quoteprov.so.
 * This causes a crash in libssl.so. (See
 * https://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=2325).
 * Keeping libngsa_quoteprov.so pinned in memory solves the libssl.so crash.
 */

static void* _lib_handle = 0;
static sgx_ql_get_revocation_info_t _get_revocation_info = 0;
static sgx_ql_free_revocation_info_t _free_revocation_info = 0;

static void _unload_quote_provider()
{
    if (_lib_handle)
    {
        dlclose(_lib_handle);
        _lib_handle = 0;
    }
}

static void _quote_provider_log(sgx_ql_log_level_t level, const char* message)
{
    const char* level_string = level == 0 ? "ERROR" : "INFO";
    char formatted[1024];

    snprintf(formatted, sizeof(formatted), "[%s]: %s\n", level_string, message);

    formatted[sizeof(formatted) - 1] = 0;

    printf("%s", formatted);
}

static void _load_quote_provider()
{
    if (_lib_handle == 0)
    {
        _lib_handle = dlopen("libngsa_quoteprov.so", RTLD_LAZY | RTLD_LOCAL);
        if (_lib_handle != 0)
        {
            _get_revocation_info =
                dlsym(_lib_handle, "sgx_ql_get_revocation_info");
            _free_revocation_info =
                dlsym(_lib_handle, "sgx_ql_free_revocation_info");

            OE_TRACE_INFO(
                "sgxquoteprovider: _get_revocation_info = 0x%lx\n",
                (uint64_t)_get_revocation_info);
            OE_TRACE_INFO(
                "sgxquoteprovider: _free_revocation_info = 0x%lx\n",
                (uint64_t)_free_revocation_info);

            sgx_ql_set_logging_function_t set_log_fcn =
                (sgx_ql_set_logging_function_t)dlsym(
                    _lib_handle, "sgx_ql_set_logging_function");
            if (set_log_fcn != NULL)
            {
                OE_UNUSED(_quote_provider_log);

                OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
                // If info tracing is enabled, install the logging function.
                set_log_fcn(_quote_provider_log);
#endif
            }
            else
            {
                OE_TRACE_INFO(
                    "sgxquoteprovider: sgx_ql_set_logging_function "
                    "not found\n");
            }
            atexit(_unload_quote_provider);
        }
        else
        {
            OE_TRACE_INFO(
                "sgxquoteprovider: libngsa_quoteprov.so not found \n");
        }
    }
}

oe_result_t oe_initialize_quote_provider()
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _load_quote_provider);
    return _lib_handle ? OE_OK : OE_FAILURE;
}

oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    sgx_ql_get_revocation_info_params_t params = {0};
    sgx_plat_error_t r = SGX_PLAT_ERROR_OUT_OF_MEMORY;
    sgx_ql_revocation_info_t* revocationInfo = NULL;
    uint32_t hostBufferSize = 0;
    uint8_t* p = 0;

    if (!_get_revocation_info || !_free_revocation_info)
        OE_RAISE(OE_QUOTE_PROVIDER_LOAD_ERROR);

    params.version = SGX_QL_REVOCATION_INFO_VERSION_1;
    params.fmspc = args->fmspc;
    params.fmspc_size = sizeof(args->fmspc);
    params.crl_urls = args->crl_urls;
    params.crl_url_count = args->num_crl_urls;

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    // If info tracing is enabled, install the logging function.
    OE_TRACE_INFO("input: fmspc = \n");
    oe_hex_dump(params.fmspc, params.fmspc_size);
    for (uint32_t i = 0; i < params.crl_url_count; ++i)
    {
        OE_TRACE_INFO("input: crl_url[%d] = %s\n", i, params.crl_urls[i]);
    }
#endif

    r = _get_revocation_info(&params, &revocationInfo);

    if (r != SGX_PLAT_ERROR_OK || revocationInfo == NULL)
    {
        OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
    }

    if (revocationInfo->tcb_info == NULL || revocationInfo->tcb_info_size == 0)
    {
        OE_TRACE_INFO("tcb_info is NULL.\n");
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }
    hostBufferSize += revocationInfo->tcb_info_size + 1;

    if (revocationInfo->tcb_issuer_chain == NULL ||
        revocationInfo->tcb_issuer_chain_size == 0)
    {
        OE_TRACE_INFO("tcb_issuer_chain is NULL.\n");
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }
    hostBufferSize += revocationInfo->tcb_issuer_chain_size + 1;

    if (revocationInfo->crl_count != args->num_crl_urls)
    {
        OE_TRACE_INFO(
            "crl_count mismatch: %d != %d.\n",
            revocationInfo->crl_count,
            numCrlUrls);
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    for (uint32_t i = 0; i < revocationInfo->crl_count; ++i)
    {
        if (revocationInfo->crls[i].crl_data == NULL ||
            revocationInfo->crls[i].crl_data_size == 0)
        {
            OE_TRACE_INFO("crl[%d].crl_data is NULL.\n", i);
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
        }
        hostBufferSize += revocationInfo->crls[i].crl_data_size + 1;

        if (revocationInfo->crls[i].crl_issuer_chain == NULL ||
            revocationInfo->crls[i].crl_issuer_chain_size == 0)
        {
            OE_TRACE_INFO("crl[%d].crl_issuer_chain is NULL.\n", i);
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
        }
        hostBufferSize += revocationInfo->crls[i].crl_issuer_chain_size + 1;
    }

    OE_TRACE_INFO("sgx_ql_get_revocation_info succeeded.\n");

    p = (uint8_t*)calloc(1, hostBufferSize);
    if (p == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    args->host_out_buffer = p;

    if (revocationInfo->tcb_info != NULL)
    {
        args->tcb_info = p;
        args->tcb_info_size = revocationInfo->tcb_info_size;
        memcpy(args->tcb_info, revocationInfo->tcb_info, args->tcb_info_size);
        p += args->tcb_info_size + 1;
        OE_TRACE_INFO("tcb_info_size = %d\n", revocationInfo->tcb_info_size);
        OE_TRACE_INFO("tcb_info json = \n%s\n", *tcbInfo);
    }

    if (revocationInfo->tcb_issuer_chain != NULL)
    {
        args->tcb_issuer_chain = p;
        args->tcb_issuer_chain_size = revocationInfo->tcb_issuer_chain_size;
        memcpy(
            args->tcb_issuer_chain,
            revocationInfo->tcb_issuer_chain,
            args->tcb_issuer_chain_size);
        p += args->tcb_issuer_chain_size + 1;
        OE_TRACE_INFO(
            "tcb_issuer_chain_size = %d\n",
            revocationInfo->tcb_issuer_chain_size);
    }

    for (uint32_t i = 0; i < revocationInfo->crl_count; ++i)
    {
        if (revocationInfo->crls[i].crl_data != NULL)
        {
            args->crl[i] = p;
            args->crl_size[i] = revocationInfo->crls[i].crl_data_size;
            memcpy(
                args->crl[i],
                revocationInfo->crls[i].crl_data,
                args->crl_size[i]);
            p += args->crl_size[i] + 1;
            OE_TRACE_INFO(
                "crls[%d].crl_data_size = %d\n",
                i,
                revocationInfo->crls[i].crl_data_size);
        }
        if (revocationInfo->crls[i].crl_issuer_chain != NULL)
        {
            args->crl_issuer_chain[i] = p;
            args->crl_issuer_chain_size[i] =
                revocationInfo->crls[i].crl_issuer_chain_size;
            memcpy(
                args->crl_issuer_chain[i],
                revocationInfo->crls[i].crl_issuer_chain,
                args->crl_issuer_chain_size[i]);
            p += args->crl_issuer_chain_size[i] + 1;
            OE_TRACE_INFO(
                "crls[%d].crl_issuer_chain_size = %d\n",
                i,
                revocationInfo->crls[i].crl_issuer_chain_size);
        }
    }

    result = OE_OK;
done:
    if (revocationInfo != NULL)
    {
        OE_TRACE_INFO("Freeing revocation info. \n");
        _free_revocation_info(revocationInfo);
        OE_TRACE_INFO("Freed revocation info.\n");
    }

    return result;
}
