// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_enclave_common_wrapper.h"
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../hostthread.h"

/**
 * Pointers to functions that will be looked up from sgx_enclave_common.so/.dll
 */

static void* (*_enclave_create)(
    void* base_address,
    size_t virtual_size,
    size_t initial_commit,
    uint32_t type,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error);

static size_t (*_enclave_load_data)(
    void* target_address,
    size_t target_size,
    const void* source_buffer,
    uint32_t data_properties,
    uint32_t* enclave_error);

bool (*_enclave_initialize)(
    void* base_address,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error);

bool (*_enclave_delete)(void* base_address, uint32_t* enclave_error);

static bool (*_enclave_set_information)(
    void* base_address,
    uint32_t info_type,
    void* input_info,
    size_t input_info_size,
    uint32_t* enclave_error);

/****** Dynamic loading of libsgx_enclave_common.so/.dll **************/

#ifdef _WIN32

#include <windows.h>

#define LIBRARY_NAME "sgx_enclave_common.dll"
// Use LOAD_LIBRARY_SEARCH_SYSTEM32 flag since sgx_enclave_common.dll is part of
// the Intel driver components and should only be loaded from there.
#define LOAD_SGX_ENCLAVE_COMMON() \
    (void*)LoadLibraryEx(LIBRARY_NAME, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);

#define LOOKUP_FUNCTION(fcn) (void*)GetProcAddress((HANDLE)_module, fcn)

#define UNLOAD_SGX_ENCLAVE_COMMON() FreeLibrary((HANDLE)_module)

#else

#include <dlfcn.h>

// Explicitly choose the version of libsgx_enclave_common.so (currently 1)
// that OE is compatible with.
#define LIBRARY_NAME "libsgx_enclave_common.so.1"

// Use best practices
// - RTLD_NOW  Bind all undefined symbols before dlopen returns.
// - RTLD_GLOBAL Make symbols from this shared library visible to
//   subsequently loaded libraries.
#define LOAD_SGX_ENCLAVE_COMMON() dlopen(LIBRARY_NAME, RTLD_NOW | RTLD_GLOBAL)

#define LOOKUP_FUNCTION(fcn) (void*)dlsym(_module, fcn)

#define UNLOAD_SGX_ENCLAVE_COMMON() dlclose(_module)

#endif

static void* _module;

static void _unload_sgx_enclave_common(void)
{
    if (_module)
    {
        UNLOAD_SGX_ENCLAVE_COMMON();
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

static void _load_sgx_enclave_common_impl(void)
{
    oe_result_t result = OE_FAILURE;
    OE_TRACE_INFO("Loading %s\n", LIBRARY_NAME);
    _module = LOAD_SGX_ENCLAVE_COMMON();

    if (_module)
    {
        OE_CHECK(_lookup_function("enclave_create", (void**)&_enclave_create));
        OE_CHECK(
            _lookup_function("enclave_load_data", (void**)&_enclave_load_data));
        OE_CHECK(_lookup_function(
            "enclave_initialize", (void**)&_enclave_initialize));
        OE_CHECK(_lookup_function("enclave_delete", (void**)&_enclave_delete));
        OE_CHECK(_lookup_function(
            "enclave_set_information", (void**)&_enclave_set_information));

        atexit(_unload_sgx_enclave_common);
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
        // It is a catastrophic error if sgx_enclave_common library cannot be
        // successfully loaded.
        OE_TRACE_ERROR("Terminating host application.");
        abort();
    }
}

static bool _load_sgx_enclave_common(void)
{
    static oe_once_type _once;
    oe_once(&_once, _load_sgx_enclave_common_impl);
    return (_module != NULL);
}

void* oe_sgx_enclave_create(
    void* base_address,
    size_t virtual_size,
    size_t initial_commit,
    uint32_t type,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error)
{
    _load_sgx_enclave_common();
    return _enclave_create(
        base_address,
        virtual_size,
        initial_commit,
        type,
        info,
        info_size,
        enclave_error);
}

size_t oe_sgx_enclave_load_data(
    void* target_address,
    size_t target_size,
    const void* source_buffer,
    uint32_t data_properties,
    uint32_t* enclave_error)
{
    return _enclave_load_data(
        target_address,
        target_size,
        source_buffer,
        data_properties,
        enclave_error);
}

bool oe_sgx_enclave_initialize(
    void* base_address,
    const void* info,
    size_t info_size,
    uint32_t* enclave_error)
{
    return _enclave_initialize(base_address, info, info_size, enclave_error);
}

bool oe_sgx_enclave_delete(void* base_address, uint32_t* enclave_error)
{
    return _enclave_delete(base_address, enclave_error);
}

bool oe_sgx_enclave_set_information(
    void* base_address,
    uint32_t info_type,
    void* input_info,
    size_t input_info_size,
    uint32_t* enclave_error)
{
    return _enclave_set_information(
        base_address, info_type, input_info, input_info_size, enclave_error);
}
