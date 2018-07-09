// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 2

#include <dlfcn.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hostthread.h"
#include "platformquoteprovider.h"
#include "sgxquoteprovider.h"

static void* g_LibHandle = 0;
static sgx_ql_get_revocation_info_t g_GetRevocationInfo = 0;
static sgx_ql_free_revocation_info_t g_FreeRevocationInfo = 0;

static void _UnloadQuoteProvider()
{
    if (g_LibHandle)
    {
        dlclose(g_LibHandle);
        g_LibHandle = 0;
    }
}

static void _QuoteProviderLog(sgx_ql_log_level_t level, const char* message)
{
    const char* levelString = level == 0 ? "ERROR" : "INFO";
    char formatted[1024];

    snprintf(formatted, sizeof(formatted), "[%s]: %s\n", levelString, message);

    formatted[sizeof(formatted) - 1] = 0;

    printf("%s", formatted);
}

static void _LoadQuoteProvider()
{
    if (g_LibHandle == 0)
    {
        g_LibHandle = dlopen("libngsa_quoteprov.so", RTLD_LAZY | RTLD_LOCAL);
        if (g_LibHandle != 0)
        {
            g_GetRevocationInfo =
                dlsym(g_LibHandle, "sgx_ql_get_revocation_info");
            g_FreeRevocationInfo =
                dlsym(g_LibHandle, "sgx_ql_free_revocation_info");

            OE_TRACE_INFO(
                "sgxquoteprovider: g_GetRevocationInfo = 0x%lx\n",
                (uint64_t)g_GetRevocationInfo);
            OE_TRACE_INFO(
                "sgxquoteprovider: g_FreeRevocationInfo = 0x%lx\n",
                (uint64_t)g_FreeRevocationInfo);

            sgx_ql_set_logging_function_t set_log_fcn =
                (sgx_ql_set_logging_function_t)dlsym(
                    g_LibHandle, "sgx_ql_set_logging_function");
            if (set_log_fcn != NULL)
            {
                OE_UNUSED(_QuoteProviderLog);

                OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
                // If info tracing is enabled, install the logging function.
                set_log_fcn(_QuoteProviderLog);
#endif
            }
            else
            {
                OE_TRACE_INFO(
                    "sgxquoteprovider: sgx_ql_set_logging_function "
                    "not found\n");
            }
            atexit(_UnloadQuoteProvider);
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
    oe_once(&once, _LoadQuoteProvider);
    return g_LibHandle ? OE_OK : OE_FAILURE;
}

oe_result_t oe_get_revocation_info(
    uint8_t fmspc[6],               /* in */
    const char* crlUrls[3],         /* in */
    uint32_t numCrlUrls,            /* in */
    uint8_t** tcbInfo,              /* out */
    uint32_t* tcbInfoSize,          /* out */
    uint8_t** tcbIssuerChain,       /* out */
    uint32_t* tcbIssuerChainSize,   /* out */
    uint8_t* crl[3],                /* out */
    uint32_t crlSize[3],            /* out */
    uint8_t* crlIssuerChain[3],     /* out */
    uint32_t crlIssuerChainSize[3], /* out */
    uint8_t** hostOutBuffer)
{
    oe_result_t result = OE_FAILURE;
    sgx_ql_get_revocation_info_params_t params = {0};
    sgx_plat_error_t r = SGX_PLAT_ERROR_OUT_OF_MEMORY;
    sgx_ql_revocation_info_t* revocationInfo = NULL;
    uint32_t hostBufferSize = 0;
    uint8_t* p = 0;

    printf("herex\n");
    if (!g_GetRevocationInfo || !g_FreeRevocationInfo)
        OE_RAISE(OE_FAILURE);

    params.version = SGX_QL_REVOCATION_INFO_VERSION_1;
    params.fmspc = fmspc;
    params.fmspc_size = 6;
    params.crl_urls = crlUrls;
    params.crl_url_count = numCrlUrls;

#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
    // If info tracing is enabled, install the logging function.
    OE_TRACE_INFO("input: fmspc = \n");
    oe_hex_dump(params.fmspc, params.fmspc_size);
    for (uint32_t i = 0; i < params.crl_url_count; ++i)
    {
        OE_TRACE_INFO("input: crl_url[%d] = %s\n", i, params.crl_urls[i]);
    }
#endif

    r = g_GetRevocationInfo(&params, &revocationInfo);

    if (r != SGX_PLAT_ERROR_OK || revocationInfo == NULL)
    {
        OE_RAISE(OE_FAILURE);
    }

    if (revocationInfo->tcb_info == NULL || revocationInfo->tcb_info_size == 0)
    {
        OE_TRACE_INFO("tcb_info is NULL.\n");
        OE_RAISE(OE_FAILURE);
    }
    hostBufferSize += revocationInfo->tcb_info_size;

    if (revocationInfo->tcb_issuer_chain == NULL ||
        revocationInfo->tcb_issuer_chain_size == 0)
    {
        OE_TRACE_INFO("tcb_issuer_chain is NULL.\n");
        OE_RAISE(OE_FAILURE);
    }
    hostBufferSize += revocationInfo->tcb_issuer_chain_size;

    if (revocationInfo->crl_count != numCrlUrls)
    {
        OE_TRACE_INFO(
            "crl_count mismatch: %d != %d.\n",
            revocationInfo->crl_count,
            numCrlUrls);
        OE_RAISE(OE_FAILURE);
    }

    for (uint32_t i = 0; i < revocationInfo->crl_count; ++i)
    {
        if (revocationInfo->crls[i].crl_data == NULL ||
            revocationInfo->crls[i].crl_data_size == 0)
        {
            OE_TRACE_INFO("crl[%d].crl_data is NULL.\n", i);
            OE_RAISE(OE_FAILURE);
        }
        hostBufferSize += revocationInfo->crls[i].crl_data_size;

        if (revocationInfo->crls[i].crl_issuer_chain == NULL ||
            revocationInfo->crls[i].crl_issuer_chain_size == 0)
        {
            OE_TRACE_INFO("crl[%d].crl_issuer_chain is NULL.\n", i);
            OE_RAISE(OE_FAILURE);
        }
        hostBufferSize += revocationInfo->crls[i].crl_issuer_chain_size;
    }

    OE_TRACE_INFO("sgx_ql_get_revocation_info succeeded.\n");

    p = (uint8_t*)malloc(hostBufferSize + 1024);
    if (p == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    *hostOutBuffer = p;

    if (revocationInfo->tcb_info != NULL)
    {
        *tcbInfo = p;
        *tcbInfoSize = revocationInfo->tcb_info_size;
        memcpy(*tcbInfo, revocationInfo->tcb_info, *tcbInfoSize);
        p += *tcbInfoSize;
        OE_TRACE_INFO("tcb_info_size = %d\n", revocationInfo->tcb_info_size);
    }

    if (revocationInfo->tcb_issuer_chain != NULL)
    {
        *tcbIssuerChain = p;
        *tcbIssuerChainSize = revocationInfo->tcb_issuer_chain_size;
        memcpy(
            *tcbIssuerChain,
            revocationInfo->tcb_issuer_chain,
            *tcbIssuerChainSize);
        p += *tcbIssuerChainSize;
        OE_TRACE_INFO(
            "tcb_issuer_chain_size = %d\n",
            revocationInfo->tcb_issuer_chain_size);
    }

    for (uint32_t i = 0; i < revocationInfo->crl_count; ++i)
    {
        if (revocationInfo->crls[i].crl_data != NULL)
        {
            crl[i] = p;
            crlSize[i] = revocationInfo->crls[i].crl_data_size;
            memcpy(crl[i], revocationInfo->crls[i].crl_data, crlSize[i]);
            p += crlSize[i];
            OE_TRACE_INFO(
                "crls[%d].crl_data_size = %d\n",
                i,
                revocationInfo->crls[i].crl_data_size);
        }
        if (revocationInfo->crls[i].crl_issuer_chain != NULL)
        {
            crlIssuerChain[i] = p;
            crlIssuerChainSize[i] =
                revocationInfo->crls[i].crl_issuer_chain_size;
            memcpy(
                crlIssuerChain[i],
                revocationInfo->crls[i].crl_issuer_chain,
                crlIssuerChainSize[i]);
            p += crlIssuerChainSize[i];
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
        g_FreeRevocationInfo(revocationInfo);
        OE_TRACE_INFO("Freed revocation info.\n");
    }

    return result;
}
