// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <dlfcn.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../sgxquoteprovider.h"

oe_sgx_quote_provider_t provider = {0};

static void _unload_quote_provider()
{
    OE_TRACE_INFO("_unload_quote_provider libdcap_quoteprov.so\n");
    if (provider.handle)
    {
        dlclose(provider.handle);
        provider.handle = 0;
    }
}

void oe_load_quote_provider()
{
    if (provider.handle == 0)
    {
        OE_TRACE_INFO("oe_load_quote_provider libdcap_quoteprov.so\n");
        provider.handle =
            dlopen("libdcap_quoteprov.so", RTLD_LAZY | RTLD_LOCAL);
        if (provider.handle != 0)
        {
            sgx_ql_set_logging_function_t set_log_fcn =
                (sgx_ql_set_logging_function_t)dlsym(
                    provider.handle, "sgx_ql_set_logging_function");
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

            provider.get_sgx_quote_verification_collateral = dlsym(
                provider.handle, SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME);
            provider.free_sgx_quote_verification_collateral = dlsym(
                provider.handle,
                SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.get_sgx_quote_verification_collateral "
                "= 0x%lx\n",
                (uint64_t)provider.get_sgx_quote_verification_collateral);
            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.get_sgx_quote_verification_collateral "
                "= 0x%lx\n",
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
        }
        else
        {
            OE_TRACE_ERROR(
                "sgxquoteprovider: libdcap_quoteprov.so %s\n", dlerror());
        }
    }
}
