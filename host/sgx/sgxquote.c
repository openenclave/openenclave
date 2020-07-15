// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxquote.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include <string.h>
#include "../hostthread.h"

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

static quote3_error_t (*_sgx_qe_get_target_info)(
    sgx_target_info_t* p_qe_target_info);

static quote3_error_t (*_sgx_qe_get_quote_size)(uint32_t* p_quote_size);

static quote3_error_t (*_sgx_qe_get_quote)(
    const sgx_report_t* p_app_report,
    uint32_t quote_size,
    uint8_t* p_quote);

#ifdef _WIN32

#include <windows.h>

#define LIBRARY_NAME "sgx_dcap_ql.dll"
// Use LOAD_LIBRARY_SEARCH_SYSTEM32 flag since sgx_enclave_common.dll is part of
// the Intel driver components and should only be loaded from there.
#define LOAD_SGX_DCAP_QL() \
    (void*)LoadLibraryEx(LIBRARY_NAME, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

#define LOOKUP_FUNCTION(fcn) (void*)GetProcAddress((HANDLE)_module, fcn)

#define UNLOAD_SGX_DCAP_QL() FreeLibrary((HANDLE)_module)

#else

#include <dlfcn.h>

#define LIBRARY_NAME "libsgx_dcap_ql.so"

// Use best practices
// - RTLD_NOW  Bind all undefined symbols before dlopen returns.
// - RTLD_GLOBAL Make symbols from this shared library visible to
//   subsequently loaded libraries.
#define LOAD_SGX_DCAP_QL() dlopen(LIBRARY_NAME, RTLD_NOW | RTLD_GLOBAL)

#define LOOKUP_FUNCTION(fcn) (void*)dlsym(_module, fcn)

#define UNLOAD_SGX_DCAP_QL() dlclose(_module)

#endif

static void* _module;

static void _unload_sgx_dcap_ql(void)
{
    if (_module)
    {
        UNLOAD_SGX_DCAP_QL();
        _module = NULL;
    }
}

static oe_result_t _lookup_function(const char* name, void** function_ptr)
{
    oe_result_t result = OE_FAILURE;
    *function_ptr = LOOKUP_FUNCTION(name);
    if (!*function_ptr)
    {
        OE_TRACE_ERROR("%s function not found.\n", name);
        goto done;
    }
    result = OE_OK;
done:
    return result;
}

static void _load_sgx_dcap_ql_impl(void)
{
    oe_result_t result = OE_FAILURE;
    OE_TRACE_INFO("Loading %s\n", LIBRARY_NAME);
    _module = LOAD_SGX_DCAP_QL();

    if (_module)
    {
        OE_CHECK(_lookup_function(
            "sgx_qe_get_target_info", (void**)&_sgx_qe_get_target_info));
        OE_CHECK(_lookup_function(
            "sgx_qe_get_quote_size", (void**)&_sgx_qe_get_quote_size));
        OE_CHECK(
            _lookup_function("sgx_qe_get_quote", (void**)&_sgx_qe_get_quote));

        atexit(_unload_sgx_dcap_ql);
        result = OE_OK;
        OE_TRACE_INFO("Loaded %s\n", LIBRARY_NAME);
    }
    else
    {
        OE_TRACE_ERROR("Failed to load %s\n", LIBRARY_NAME);
        goto done;
    }

done:
    if (result != OE_OK)
    {
        // It is a catastrophic error if sgx_dcap_ql library cannot be
        // successfully loaded.
        OE_TRACE_ERROR("Terminating host application.");
        abort();
    }
}

static bool _load_sgx_dcap_ql(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_sgx_dcap_ql_impl);
    return (_module != NULL);
}

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info)
{
    oe_result_t result = OE_FAILURE;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    _load_sgx_dcap_ql();
    err = _sgx_qe_get_target_info((sgx_target_info_t*)target_info);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_FAILURE;
    uint32_t* local_quote_size = (uint32_t*)quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);
    _load_sgx_dcap_ql();
    err = _sgx_qe_get_quote_size(local_quote_size);

    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote)
{
    oe_result_t result = OE_FAILURE;
    uint32_t local_quote_size = 0;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    OE_UNUSED(format_id);
    OE_UNUSED(opt_params);
    OE_UNUSED(opt_params_size);

    if (quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

    local_quote_size = (uint32_t)quote_size;
    _load_sgx_dcap_ql();

    err = _sgx_qe_get_quote((sgx_report_t*)report, local_quote_size, quote);
    if (err != SGX_QL_SUCCESS)
        OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);
    OE_TRACE_INFO("quote_size=%d", local_quote_size);

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size)
{
    const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};
    oe_result_t result = OE_FAILURE;

    if (!format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Case when DCAP is used
    if (!format_ids && *format_ids_size == 0)
    {
        *format_ids_size = sizeof(oe_uuid_t);
        return OE_BUFFER_TOO_SMALL;
    }
    else if (!format_ids || *format_ids_size < sizeof(oe_uuid_t))
    {
        *format_ids_size = sizeof(oe_uuid_t);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    memcpy(format_ids, &_ecdsa_uuid, sizeof(oe_uuid_t));
    *format_ids_size = sizeof(oe_uuid_t);

    result = OE_OK;

done:
    return result;
}
