// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <Windows.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../sgxquoteprovider.h"

oe_sgx_quote_provider_t provider = {0};

static void _unload_quote_provider(void)
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
            sgx_ql_set_logging_function_t set_log_fcn =
                (sgx_ql_set_logging_function_t)GetProcAddress(
                    _handle, SGX_QL_SET_LOGGING_FUNCTION_NAME);
            if (set_log_fcn != NULL)
            {
                OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
                if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
                {
                    // If info tracing is enabled, install the logging function.
                    set_log_fcn(oe_quote_provider_log);
                }
            }
            else
            {
                OE_TRACE_WARNING(
                    "sgxquoteprovider: sgx_ql_set_logging_function "
                    "not found\n");
            }

            provider.get_sgx_quote_verification_collateral =
                (sgx_get_quote_verification_collateral_t)GetProcAddress(
                    _handle, SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME);
            provider.free_sgx_quote_verification_collateral =
                (sgx_free_quote_verification_collateral_t)GetProcAddress(
                    _handle, SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.get_sgx_quote_verification_collateral = 0x%lx\n",
                (uint64_t)provider.get_sgx_quote_verification_collateral);
            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.free_sgx_quote_verification_collateral = 0x%lx\n",
                (uint64_t)provider.free_sgx_quote_verification_collateral);

            if (provider.get_sgx_quote_verification_collateral == NULL ||
                provider.free_sgx_quote_verification_collateral == NULL)
            {
                OE_TRACE_ERROR(
                    "sgxquoteprovider: get_sgx_quote_verification_collateral "
                    "or free_sgx_quote_verification_collateral not found\n"
                    "If you are using Azure DCAP client, please make sure its "
                    "version is greater or equal to 1.2\n");
            }

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
