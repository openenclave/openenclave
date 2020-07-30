// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxquote.h"
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/plugin.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <sgx_ql_lib_common.h>
#include <sgx_quote_3.h>
#include <sgx_uae_quote_ex.h>
#include <stdlib.h>
#include <string.h>
#include "../../common/oe_host_stdlib.h"
#include "../hostthread.h"
#include "sgxquote_ex.h"

// Check consistency with OE definition.
OE_STATIC_ASSERT(sizeof(sgx_target_info_t) == 512);
OE_STATIC_ASSERT(sizeof(sgx_report_t) == 432);

static const oe_uuid_t _ecdsa_p256_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P256};

OE_STATIC_ASSERT(sizeof(sgx_att_key_id_ext_t) == sizeof(sgx_att_key_id_t));

// Redefine some constants in <sgx_quote_3.h> to be more meaningful
#define SGX_QL_ALG_EPID_UNLINKABLE SGX_QL_ALG_EPID
#define SGX_QL_ALG_EPID_LINKABLE SGX_QL_ALG_RESERVED_1

static oe_sgx_quote_ex_library_t _quote_ex_library = {0};
static const oe_uuid_t _unknown_uuid = {OE_FORMAT_UUID_SGX_UNKNOWN};
static const oe_uuid_t _ecdsa_p384_uuid = {OE_FORMAT_UUID_SGX_ECDSA_P384};
static const oe_uuid_t _epid_linkable_uuid = {OE_FORMAT_UUID_SGX_EPID_LINKABLE};
static const oe_uuid_t _epid_unlinkable_uuid = {
    OE_FORMAT_UUID_SGX_EPID_UNLINKABLE};

static sgx_att_key_id_ext_t* _format_id_to_key_id(const oe_uuid_t* format_id)
{
    if (!format_id)
        return NULL;

    for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
    {
        if (!_quote_ex_library.mapped[i])
            continue;

        if (!memcmp(format_id, _quote_ex_library.uuid + i, sizeof(oe_uuid_t)))
            return _quote_ex_library.sgx_key_id + i;
    }

    return NULL;
}

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

#define SGX_DCAP_IN_PROCESS_QUOTING() \
    (GetEnvironmentVariableA("SGX_AESM_ADDR", NULL, 0) == 0)

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

#define SGX_DCAP_IN_PROCESS_QUOTING() (getenv("SGX_AESM_ADDR") == NULL)

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
        OE_TRACE_WARNING("Failed to load %s\n", LIBRARY_NAME);
        goto done;
    }

done:
    if (result != OE_OK)
    {
        OE_TRACE_WARNING("Alternative quoting library will be needed.");
    }
}

static bool _load_sgx_dcap_ql(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_sgx_dcap_ql_impl);
    return (_module != NULL);
}

static void _load_quote_ex_library_once(void)
{
    bool* local_mapped = NULL;
    oe_uuid_t* local_uuid = NULL;
    sgx_att_key_id_ext_t* local_key_id = NULL;
    oe_result_t result = OE_UNEXPECTED;

    if (_load_sgx_dcap_ql() && SGX_DCAP_IN_PROCESS_QUOTING())
    {
        OE_TRACE_INFO("DCAP installed and set for in-process quoting.");
        _quote_ex_library.use_dcap_library_instead = true;
        return;
    }
    else
    {
        OE_TRACE_INFO(
            "DCAP not installed or set for out-of-process, try quote-ex");
        _quote_ex_library.use_dcap_library_instead = false;
    }

    if (_quote_ex_library.handle && _quote_ex_library.load_result == OE_OK)
        return;

    oe_sgx_load_quote_ex_library(&_quote_ex_library);
    if (_quote_ex_library.load_result == OE_OK)
    {
        uint32_t att_key_id_num = 0;
        uint32_t mapped_key_id_count = 0;
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        status =
            _quote_ex_library.sgx_get_supported_att_key_id_num(&att_key_id_num);
        if (status != SGX_SUCCESS || att_key_id_num == 0)
        {
            OE_TRACE_ERROR(
                "_load_quote_ex_library_once() "
                "sgx_get_supported_att_key_id_num() status=%d num=%d\n",
                status,
                att_key_id_num);
            OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
        }

        local_mapped = (bool*)oe_malloc(att_key_id_num * sizeof(bool));
        local_uuid = (oe_uuid_t*)oe_malloc(att_key_id_num * sizeof(oe_uuid_t));
        local_key_id = (sgx_att_key_id_ext_t*)oe_malloc(
            att_key_id_num * sizeof(sgx_att_key_id_ext_t));

        if (!local_mapped || !local_uuid || !local_key_id)
            OE_RAISE(OE_OUT_OF_MEMORY);

        status = _quote_ex_library.sgx_get_supported_att_key_ids(
            local_key_id, att_key_id_num);
        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "_load_quote_ex_library_once() "
                "sgx_get_supported_att_key_ids() status=%d\n",
                status);

        for (uint32_t i = 0; i < att_key_id_num; i++)
        {
            sgx_att_key_id_ext_t* key = local_key_id + i;
            const oe_uuid_t* uuid = NULL;

            OE_TRACE_INFO("algorithm_id=%d", key->base.algorithm_id);

            switch (key->base.algorithm_id)
            {
                case SGX_QL_ALG_EPID_UNLINKABLE:
                    uuid = &_epid_unlinkable_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_EPID_LINKABLE:
                    uuid = &_epid_linkable_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_ECDSA_P256:
                    uuid = &_ecdsa_p256_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                case SGX_QL_ALG_ECDSA_P384:
                    uuid = &_ecdsa_p384_uuid;
                    local_mapped[i] = true;
                    mapped_key_id_count++;
                    break;
                default:
                    uuid = &_unknown_uuid;
                    local_mapped[i] = false;
                    OE_TRACE_ERROR(
                        "algorithm_id=%d maps to no uuid",
                        key->base.algorithm_id);
                    break;
            }
            memcpy(local_uuid + i, uuid, sizeof(oe_uuid_t));
        }

        _quote_ex_library.key_id_count = att_key_id_num;
        _quote_ex_library.mapped_key_id_count = mapped_key_id_count;
        _quote_ex_library.mapped = local_mapped;
        _quote_ex_library.uuid = local_uuid;
        _quote_ex_library.sgx_key_id = local_key_id;
        local_mapped = NULL;
        local_uuid = NULL;
        local_key_id = NULL;

        OE_TRACE_INFO(
            "key_id_count=%lu mapped=%lu\n",
            att_key_id_num,
            mapped_key_id_count);

        result = OE_OK;
    }

done:
    if (local_mapped)
    {
        oe_free(local_mapped);
        local_mapped = NULL;
    }
    if (local_uuid)
    {
        oe_free(local_uuid);
        local_uuid = NULL;
    }
    if (local_key_id)
    {
        oe_free(local_key_id);
        local_key_id = NULL;
    }
    if (_quote_ex_library.load_result == OE_OK)
        _quote_ex_library.load_result = result;

    OE_TRACE_INFO(
        "_load_quote_ex_library_once() result=%s\n",
        oe_result_str(_quote_ex_library.load_result));

    return;
}

// For choosing between the DCAP library and the quote-ex library for quote
// generation: the DCAP library is used if it can be loaded and is configured
// to do in-process quote generation. Otherwise, if the DCAP library can't
// be loaded or it is configured to do out-of-process quote generation,
// we will try to use the quote-ex library instead.
// Please refer to the design document SGX_QuoteEx_Integration.md for more
// information on how the quote-ex library is integrated.

static bool _use_quote_ex_library(void)
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _load_quote_ex_library_once);

    return (
        (!_quote_ex_library.use_dcap_library_instead) &&
        _quote_ex_library.load_result == OE_OK);
}

oe_result_t oe_sgx_qe_get_target_info(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* target_info)
{
    oe_result_t result = OE_UNEXPECTED;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !target_info)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};
        size_t local_size = 0;
        uint8_t* local_buffer = NULL;
        sgx_target_info_t local_target_info;

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &local_target_info,
            &local_size,
            NULL);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_init_quote_ex(NULL) returned 0x%x\n",
                status);

        local_buffer = (uint8_t*)oe_malloc(local_size);
        if (!local_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        status = _quote_ex_library.sgx_init_quote_ex(
            (sgx_att_key_id_t*)&updated_key_id,
            &local_target_info,
            &local_size,
            local_buffer);
        oe_free(local_buffer);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_init_quote_ex(local_buffer) returned 0x%x\n",
                status);

        memcpy(target_info, &local_target_info, sizeof(sgx_target_info_t));

        result = OE_OK;
    }
    else
    {
        _load_sgx_dcap_ql();
        err = _sgx_qe_get_target_info((sgx_target_info_t*)target_info);

        if (err != SGX_QL_SUCCESS)
            OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

        result = OE_OK;
    }
done:
    return result;
}

oe_result_t oe_sgx_qe_get_quote_size(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    size_t* quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)*quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !quote_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params && opt_params_size == sizeof(key_id->spid))
                memcpy(updated_key_id.spid, opt_params, opt_params_size);
        }

        status = _quote_ex_library.sgx_get_quote_size_ex(
            (const sgx_att_key_id_t*)&updated_key_id, &local_quote_size);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_get_quote_size_ex() returned 0x%x\n",
                status);

        OE_TRACE_INFO("local_quote_size = %lu\n", local_quote_size);

        *quote_size = local_quote_size;
        result = OE_OK;
    }
    else
    {
        _load_sgx_dcap_ql();
        err = _sgx_qe_get_quote_size(&local_quote_size);

        if (err != SGX_QL_SUCCESS)
            OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);

        *quote_size = local_quote_size;
        result = OE_OK;
    }
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
    oe_result_t result = OE_UNEXPECTED;
    uint32_t local_quote_size = (uint32_t)quote_size;
    quote3_error_t err = SGX_QL_ERROR_UNEXPECTED;

    if (!format_id || !report || !quote || !quote_size ||
        quote_size > OE_MAX_UINT32)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        sgx_att_key_id_ext_t updated_key_id = {{0}};

        sgx_att_key_id_ext_t* key_id = _format_id_to_key_id(format_id);
        if (!key_id)
            OE_RAISE(OE_UNSUPPORTED);

        // Update key ID with input SP ID for EPID quoting
        memcpy(&updated_key_id, key_id, sizeof(*key_id));
        if (key_id->base.algorithm_id == SGX_QL_ALG_EPID_LINKABLE ||
            key_id->base.algorithm_id == SGX_QL_ALG_EPID_UNLINKABLE)
        {
            if (opt_params)
            {
                if (opt_params_size == sizeof(key_id->spid))
                    memcpy(updated_key_id.spid, opt_params, opt_params_size);
                else
                {
                    OE_TRACE_INFO(
                        "EPID requires opt_params to be 16-byte SPID");
                    OE_RAISE(OE_INVALID_PARAMETER);
                }
            }
        }
        else // ECDSA
        {
            // For EPID, no opt_params is taken.
            if (opt_params || opt_params_size)
                OE_RAISE(OE_INVALID_PARAMETER);
        }

        status = _quote_ex_library.sgx_get_quote_ex(
            (const sgx_report_t*)report,
            (const sgx_att_key_id_t*)&updated_key_id,
            NULL,
            quote,
            local_quote_size);

        if (status != SGX_SUCCESS)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "sgx_get_quote_ex() returned 0x%x\n",
                status);

        OE_TRACE_INFO(
            "quote_ex got quote for algorithm_id=%d\n",
            key_id->base.algorithm_id);

        result = OE_OK;
    }
    else
    {
        if (quote_size > OE_MAX_UINT32)
            OE_RAISE(OE_INVALID_PARAMETER);

        local_quote_size = (uint32_t)quote_size;
        _load_sgx_dcap_ql();

        err = _sgx_qe_get_quote((sgx_report_t*)report, local_quote_size, quote);
        if (err != SGX_QL_SUCCESS)
            OE_RAISE_MSG(OE_PLATFORM_ERROR, "quote3_error_t=0x%x\n", err);
        OE_TRACE_INFO("quote_size=%d", local_quote_size);

        result = OE_OK;
    }
done:
    return result;
}

oe_result_t oe_sgx_get_supported_attester_format_ids(
    void* format_ids,
    size_t* format_ids_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!format_ids_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (_use_quote_ex_library())
    {
        size_t count = _quote_ex_library.mapped_key_id_count;
        size_t index = 0;

        if (count &&
            (!format_ids || *format_ids_size < sizeof(oe_uuid_t) * count))
        {
            *format_ids_size = sizeof(oe_uuid_t) * count;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        for (size_t i = 0; i < _quote_ex_library.key_id_count; i++)
        {
            // Skip the entry if it was not mapped.
            if (!_quote_ex_library.mapped[i])
                continue;

            memcpy(
                ((uint8_t*)format_ids) + sizeof(oe_uuid_t) * index,
                _quote_ex_library.uuid + i,
                sizeof(oe_uuid_t));
            index++;
        }

        *format_ids_size = sizeof(oe_uuid_t) * count;

        OE_TRACE_INFO("quote_ex got %lu format IDs\n", count);

        result = OE_OK;
    }
    else
    {
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
        memcpy(format_ids, &_ecdsa_p256_uuid, sizeof(oe_uuid_t));
        *format_ids_size = sizeof(oe_uuid_t);

        OE_TRACE_INFO("DCAP only supports ECDSA_P256\n");
        result = OE_OK;
    }
done:
    return result;
}
