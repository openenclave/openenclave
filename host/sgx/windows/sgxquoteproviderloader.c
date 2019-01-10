// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../sgxquoteprovider.h"

#ifdef OE_USE_LIBSGX

oe_sgx_quote_provider_t provider = {0};

static void _unload_quote_provider()
{
    OE_TRACE_INFO("_unload_quote_provider dcap_quoteprov.dll\n");
    if (provider.handle)
    {
        FreeLibrary((HMODULE)provider.handle);
        provider.handle = 0;
    }
}

void oe_load_quote_provider()
{
    if (provider.handle == 0)
    {
        OE_TRACE_INFO("oe_load_quote_provider dcap_quoteprov.dll\n");
        HMODULE _handle = LoadLibraryEx("dcap_quoteprov.dll", NULL, 0);
        if (_handle != 0)
        {
            provider.get_revocation_info =
                (sgx_ql_get_revocation_info_t)GetProcAddress(
                    _handle, SGX_QL_GET_REVOCATION_INFO_NAME);
            provider.free_revocation_info =
                (sgx_ql_free_revocation_info_t)GetProcAddress(
                    _handle, SGX_QL_FREE_REVOCATION_INFO_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: provider.get_revocation_info = 0x%lx\n",
                (uint64_t)provider.get_revocation_info);
            OE_TRACE_INFO(
                "sgxquoteprovider: provider.free_revocation_info = 0x%lx\n",
                (uint64_t)provider.free_revocation_info);

            sgx_ql_set_logging_function_t set_log_fcn =
                (sgx_ql_set_logging_function_t)GetProcAddress(
                    _handle, SGX_QL_SET_LOGGING_FUNCTION_NAME);
            if (set_log_fcn != NULL)
            {
                OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
                if (get_current_logging_level() >= OE_LOG_LEVEL_INFO)
                {
                    // If info tracing is enabled, install the logging function.
                    set_log_fcn(oe_quote_provider_log);
                }
            }
            else
            {
                OE_TRACE_ERROR("sgxquoteprovider: sgx_ql_set_logging_function "
                               "not found\n");
            }

            provider.get_qe_identity_info =
                (sgx_get_qe_identity_info_t)GetProcAddress(
                    _handle, SGX_QL_GET_QE_IDENTITY_INFO_NAME);
            provider.free_qe_identity_info =
                (sgx_free_qe_identity_info_t)GetProcAddress(
                    _handle, SGX_QL_FREE_QE_IDENTITY_INFO_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: provider.get_qe_identity_info = 0x%lx\n",
                (uint64_t)provider.get_qe_identity_info);
            OE_TRACE_INFO(
                "sgxquoteprovider: provider.free_qe_identity_info = 0x%lx\n",
                (uint64_t)provider.free_qe_identity_info);

            atexit(_unload_quote_provider);
            provider.handle = _handle;
        }
        else
        {
            DWORD error = GetLastError();
            OE_TRACE_ERROR(
                "sgxquoteprovider: LoadLibraryEx on dcap_quoteprov.dll error "
                "= %#x\n",
                error);
        }
    }
}

#endif
