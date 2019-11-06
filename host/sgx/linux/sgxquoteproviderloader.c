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
            provider.get_revocation_info =
                dlsym(provider.handle, SGX_QL_GET_REVOCATION_INFO_NAME);
            provider.free_revocation_info =
                dlsym(provider.handle, SGX_QL_FREE_REVOCATION_INFO_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: provider.get_revocation_info = 0x%lx\n",
                (uint64_t)provider.get_revocation_info);
            OE_TRACE_INFO(
                "sgxquoteprovider: provider.free_revocation_info = 0x%lx\n",
                (uint64_t)provider.free_revocation_info);

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
                OE_TRACE_ERROR("sgxquoteprovider: sgx_ql_set_logging_function "
                               "not found\n");
            }

            provider.get_qe_identity_info =
                dlsym(provider.handle, SGX_QL_GET_QE_IDENTITY_INFO_NAME);
            provider.free_qe_identity_info =
                dlsym(provider.handle, SGX_QL_FREE_QE_IDENTITY_INFO_NAME);

            OE_TRACE_INFO(
                "sgxquoteprovider: provider.get_qe_identity_info = 0x%lx\n",
                (uint64_t)provider.get_qe_identity_info);
            OE_TRACE_INFO(
                "sgxquoteprovider: provider.free_qe_identity_info = 0x%lx\n",
                (uint64_t)provider.free_qe_identity_info);

            atexit(_unload_quote_provider);
        }
        else
        {
            OE_TRACE_ERROR(
                "sgxquoteprovider: libdcap_quoteprov.so %s\n", dlerror());
        }
    }
}
