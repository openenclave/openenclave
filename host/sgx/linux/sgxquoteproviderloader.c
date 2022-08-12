// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <dlfcn.h>
#include <openenclave/internal/trace.h>
#include <stdint.h>
#include <stdlib.h>
#include "../sgxquoteprovider.h"
#include "openenclave/bits/result.h"

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
            if (oe_get_current_logging_level() >= OE_LOG_LEVEL_INFO)
            {
                if (oe_sgx_set_quote_provider_logger(oe_quote_provider_log) ==
                    OE_OK)
                {
                    OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
                }
                else
                {
                    OE_TRACE_WARNING(
                        "sgxquoteprovider: Not able to install log function\n");
                }
            }

            provider.get_sgx_quote_verification_collateral = dlsym(
                provider.handle, SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_NAME);
            provider.free_sgx_quote_verification_collateral = dlsym(
                provider.handle,
                SGX_QL_FREE_QUOTE_VERIFICATION_COLLATERAL_NAME);
            provider
                .get_sgx_quote_verification_collateral_with_parameters = dlsym(
                provider.handle,
                SGX_QL_GET_QUOTE_VERIFICATION_COLLATERAL_WITH_PARAMETERS_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.get_sgx_quote_verification_collateral "
                "= 0x%lx\n",
                (uint64_t)provider.get_sgx_quote_verification_collateral);
            OE_TRACE_INFO(
                "sgxquoteprovider: "
                "provider.free_sgx_quote_verification_collateral "
                "= 0x%lx\n",
                (uint64_t)provider.free_sgx_quote_verification_collateral);
            OE_TRACE_INFO(
                "sgxquoteprovider: ",
                "provider.get_sgx_quote_verification_collateral_with_params = "
                "0x%lx\n",
                (uint64_t)provider
                    .get_sgx_quote_verification_collateral_with_parameters);

            // get_sgx_quote_verification_collateral_with_params is an optional
            // replacement for get_sgx_quote_verification_collateral, the
            // provider is good as long as either one of them is available
            if ((provider.get_sgx_quote_verification_collateral == NULL &&
                 provider.get_sgx_quote_verification_collateral_with_parameters ==
                     NULL) ||
                provider.free_sgx_quote_verification_collateral == NULL)
            {
                OE_TRACE_ERROR(
                    "sgxquoteprovider: none of "
                    "get_sgx_quote_verification_collateral and "
                    "get_sgx_quote_verification_collateral_with_params can be "
                    "found "
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

oe_result_t oe_sgx_set_quote_provider_logger(sgx_ql_logging_function_t logger)
{
    sgx_ql_set_logging_function_t set_log_fcn = NULL;
    if (provider.handle == 0)
    {
        // Quote provider is not loaded.
        return OE_QUOTE_PROVIDER_LOAD_ERROR;
    }

    set_log_fcn = (sgx_ql_set_logging_function_t)dlsym(
        provider.handle, SGX_QL_SET_LOGGING_FUNCTION_NAME);
    if (set_log_fcn == NULL)
    {
        set_log_fcn = (sgx_ql_set_logging_function_t)dlsym(
            provider.handle, SGX_QL_SET_LOGGING_CALLBACK_NAME);
    }

    if (set_log_fcn != NULL)
    {
        set_log_fcn(logger);
        return OE_OK;
    }

    OE_TRACE_WARNING("sgxquoteprovider: " SGX_QL_SET_LOGGING_FUNCTION_NAME
                     " nor " SGX_QL_SET_LOGGING_CALLBACK_NAME "can be found\n");
    return OE_UNSUPPORTED;
}
