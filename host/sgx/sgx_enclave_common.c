// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_enclave_common.h"
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../dynload.h"
#include "../hostthread.h"

/****** Pointers to functions in libsgx_enclave_common.so **************/
static void* COMM_API (*_enclave_create)(
    COMM_IN_OPT void* base_address,
    COMM_IN size_t virtual_size,
    COMM_IN size_t initial_commit,
    COMM_IN uint32_t type,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

static size_t COMM_API (*_enclave_load_data)(
    COMM_IN void* target_address,
    COMM_IN size_t target_size,
    COMM_IN_OPT const void* source_buffer,
    COMM_IN uint32_t data_properties,
    COMM_OUT_OPT uint32_t* enclave_error);

bool COMM_API (*_enclave_initialize)(
    COMM_IN void* base_address,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

bool COMM_API (*_enclave_delete)(
    COMM_IN void* base_address,
    COMM_OUT_OPT uint32_t* enclave_error);

static bool COMM_API (*_enclave_set_information)(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_IN void* input_info,
    COMM_IN size_t input_info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

/****** Dynamic loading of libsgx_enclave_common.so/.dll **************/
static void* _module;

static void _unload_libsgx_enclave_common(void)
{
    if (_module)
        oe_shared_library_unload(_module);
}

static void _load_libsgx_enclave_common_impl(void)
{
    oe_result_t result = OE_FAILURE;
    void* module = _module;
    if (!module)
    {
#if _WIN32
        const char* library_name = "sgx_enclave_common.dll";
#else
        const char* library_name = "libsgx_enclave_common.so";
#endif
        OE_TRACE_INFO("Loading %s\n", library_name);
        module = oe_shared_library_load(library_name);
        if (module)
        {
            *(void**)&_enclave_create =
                oe_shared_library_lookup(module, "enclave_create");
            if (!_enclave_create)
            {
                OE_TRACE_ERROR("enclave_create function not found.\n");
                goto done;
            }

            *(void**)&_enclave_load_data =
                oe_shared_library_lookup(module, "enclave_load_data");
            if (!_enclave_load_data)
            {
                OE_TRACE_ERROR("enclave_load_data function not found.\n");
                goto done;
            }

            *(void**)&_enclave_initialize =
                oe_shared_library_lookup(module, "enclave_initialize");
            if (!_enclave_initialize)
            {
                OE_TRACE_ERROR("enclave_initialize function not found.\n");
                goto done;
            }

            *(void**)&_enclave_delete =
                oe_shared_library_lookup(module, "enclave_delete");
            if (!_enclave_delete)
            {
                OE_TRACE_ERROR("enclave_delete function not found.\n");
                goto done;
            }

            *(void**)&_enclave_set_information =
                oe_shared_library_lookup(module, "enclave_set_information");
            if (!_enclave_set_information)
            {
                OE_TRACE_ERROR("enclave_set_information function not found.\n");
                goto done;
            }

            _module = module;
            atexit(_unload_libsgx_enclave_common);
            result = OE_OK;
            OE_TRACE_INFO("Loaded %s\n", library_name);
        }
    }

done:
    if (result != OE_OK)
    {
        if (module)
            oe_shared_library_unload(module);
    }
}

static bool _load_libsgx_enclave_common(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_libsgx_enclave_common_impl);
    return (_module != NULL);
}

/****** Wrappers for functions in libsgx_enclave_common.so **************/
void* COMM_API enclave_create(
    COMM_IN_OPT void* base_address,
    COMM_IN size_t virtual_size,
    COMM_IN size_t initial_commit,
    COMM_IN uint32_t type,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (!_load_libsgx_enclave_common())
    {
        *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return NULL;
    }
    return _enclave_create(
        base_address,
        virtual_size,
        initial_commit,
        type,
        info,
        info_size,
        enclave_error);
}

size_t COMM_API enclave_load_data(
    COMM_IN void* target_address,
    COMM_IN size_t target_size,
    COMM_IN_OPT const void* source_buffer,
    COMM_IN uint32_t data_properties,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (!_load_libsgx_enclave_common())
    {
        *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return 0;
    }
    return _enclave_load_data(
        target_address,
        target_size,
        source_buffer,
        data_properties,
        enclave_error);
}

bool COMM_API enclave_initialize(
    COMM_IN void* base_address,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (!_load_libsgx_enclave_common())
    {
        *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return false;
    }
    return _enclave_initialize(base_address, info, info_size, enclave_error);
}

bool COMM_API
enclave_delete(COMM_IN void* base_address, COMM_OUT_OPT uint32_t* enclave_error)
{
    if (!_load_libsgx_enclave_common())
    {
        *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return false;
    }
    return _enclave_delete(base_address, enclave_error);
}

bool COMM_API enclave_set_information(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_IN void* input_info,
    COMM_IN size_t input_info_size,
    COMM_OUT_OPT uint32_t* enclave_error)
{
    if (!_load_libsgx_enclave_common())
    {
        *enclave_error = ENCLAVE_NOT_SUPPORTED;
        return false;
    }
    return _enclave_set_information(
        base_address, info_type, input_info, input_info_size, enclave_error);
}
