// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/raise.h>
#include <openenclave/defs.h>

#include <openenclave/result.h>
#include <openenclave/types.h>

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "PlatformQuoteProvider.h"
#include "hostthread.h"
#include "quoteprovider.h"

// By default, the directories /lib and /usr/lib are searched.
// Use LD_LIBRARY_PATH to add specific directories to look
// for .so files.
// See http://man7.org/linux/man-pages/man3/dlopen.3.html
#define OE_PLATFORM_PROVIDER_LIBRARY_PATH "/usr/lib/libazquoteprov.so"

static quote3_error_t (*sgx_ql_get_revocation_info_fcn)(
    const sgx_ql_get_revocation_info_params_t* params,
    sgx_ql_revocation_info_t** pp_revocation_info);

static void (*sgx_ql_free_revocation_info_fcn)(
    sgx_ql_revocation_info_t* p_revocation_info);

static void* g_ProviderLibHandle = NULL;
static OE_H_OnceType g_Init = OE_H_ONCE_INITIALIZER;

static void _CleanupPlatformProviderLibrary()
{
    void* handle = g_ProviderLibHandle;
    if (handle)
    {
        g_ProviderLibHandle = NULL;

        sgx_ql_get_revocation_info_fcn = NULL;
        sgx_ql_free_revocation_info_fcn = NULL;

        dlclose(handle);
    }
}
static void _LoadPlatformProviderLibrary()
{
    void* handle =
        dlopen(OE_PLATFORM_PROVIDER_LIBRARY_PATH, RTLD_NOW | RTLD_LOCAL);

    if (handle)
    {
        sgx_ql_free_revocation_info_fcn =
            dlsym(handle, "sgx_ql_free_revocation_info");
        sgx_ql_get_revocation_info_fcn =
            dlsym(handle, "sgx_ql_get_revocation_info");

        if (sgx_ql_get_revocation_info_fcn != NULL &&
            sgx_ql_free_revocation_info_fcn != NULL)
        {
            atexit(_CleanupPlatformProviderLibrary);
            g_ProviderLibHandle = handle;
        }
    }
}

static void _CopyBuffer(
    uint8_t** dst,
    uint8_t* src,
    uint32_t size,
    uint8_t** buffer)
{
    if (src)
    {
        *dst = *buffer;
        memcpy(*dst, src, size);
        *buffer += size;
    }
}

OE_Result OE_GetRevocationInfo(OE_GetRevocationInfoArgs* revocationInfo)
{
    OE_Result result = OE_UNEXPECTED;
    sgx_ql_get_revocation_info_params_t params;
    ;
    sgx_ql_revocation_info_t* info = NULL;
    uint32_t bufferSize = 0;
    uint8_t* buffer = NULL;

    OE_H_Once(&g_Init, _LoadPlatformProviderLibrary);

    if (sgx_ql_free_revocation_info_fcn == NULL ||
        sgx_ql_get_revocation_info_fcn == NULL)
        OE_RAISE(OE_FAILURE);

    params.version = SGX_QL_REVOCATION_INFO_VERSION_1;
    params.fmspc_size = 0; // TODO
    params.fmspc = NULL;   // TODO

    if (sgx_ql_get_revocation_info_fcn(&params, &info) != SGX_QL_SUCCESS)
        OE_RAISE(OE_FAILURE);

    if (info == NULL)
        OE_RAISE(OE_FAILURE);

    bufferSize = info->tcb_info_size + info->tcb_issuer_chain_size +
                 info->crl_data_size + info->crl_issuer_chain_size;

    if (bufferSize == 0)
        OE_RAISE(OE_FAILURE);

    buffer = (uint8_t*)malloc(bufferSize);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    memset(revocationInfo, 0, sizeof(*revocationInfo));
    revocationInfo->allocatedMemory = buffer;

    revocationInfo->tcbInfoSize = info->tcb_info_size;
    revocationInfo->tcbIssuerChainSize = info->tcb_issuer_chain_size;
    revocationInfo->crlSize = info->crl_data_size;
    revocationInfo->crlIssuerChainSize = info->crl_issuer_chain_size;

    _CopyBuffer(
        &revocationInfo->tcbInfo,
        info->tcb_info,
        revocationInfo->tcbInfoSize,
        &buffer);
    _CopyBuffer(
        &revocationInfo->tcbIssuerChain,
        info->tcb_issuer_chain,
        revocationInfo->tcbIssuerChainSize,
        &buffer);
    _CopyBuffer(
        &revocationInfo->crl, info->crl_data, revocationInfo->crlSize, &buffer);
    _CopyBuffer(
        &revocationInfo->crlIssuerChain,
        info->crl_issuer_chain,
        revocationInfo->crlIssuerChainSize,
        &buffer);

done:
    if (info != NULL)
    {
        sgx_ql_free_revocation_info_fcn(info);
    }

    return result;
}
