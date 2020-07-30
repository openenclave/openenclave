// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <dlfcn.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include <string.h>
#include "../../../common/oe_host_stdlib.h"
#include "../sgxquote_ex.h"

static const char* _quote_ex_library_file_name = "libsgx_quote_ex.so.1";

static oe_sgx_quote_ex_library_t* _quote_ex_library = NULL;

static void _unload_quote_ex_library(void)
{
    if (_quote_ex_library && _quote_ex_library->handle)
    {
        OE_TRACE_INFO(
            "_unload_quote_ex_library() %s\n", _quote_ex_library_file_name);
        dlclose(_quote_ex_library->handle);
        _quote_ex_library->handle = 0;
        if (_quote_ex_library->mapped)
        {
            oe_free(_quote_ex_library->mapped);
            _quote_ex_library->mapped = NULL;
        }
        if (_quote_ex_library->uuid)
        {
            oe_free(_quote_ex_library->uuid);
            _quote_ex_library->uuid = NULL;
        }
        if (_quote_ex_library->sgx_key_id)
        {
            oe_free(_quote_ex_library->sgx_key_id);
            _quote_ex_library->sgx_key_id = NULL;
        }
    }
}

void oe_sgx_load_quote_ex_library(oe_sgx_quote_ex_library_t* library)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!library)
        OE_RAISE(OE_INVALID_PARAMETER);

    _quote_ex_library = library;

    if (library->handle == 0)
    {
        void* handle = 0;
        OE_TRACE_INFO(
            "oe_sgx_load_quote_ex_library() %s\n", _quote_ex_library_file_name);
        handle = dlopen(_quote_ex_library_file_name, RTLD_LAZY | RTLD_LOCAL);

        if (handle != 0)
        {
            library->sgx_select_att_key_id =
                dlsym(handle, SGX_SELECT_ATT_KEY_ID_NAME);
            if (!library->sgx_select_att_key_id)
            {
                OE_TRACE_ERROR(
                    "sgxquoteexprovider: sgx_select_att_key_id not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }
            library->sgx_init_quote_ex = dlsym(handle, SGX_INIT_QUOTE_EX_NAME);
            if (!library->sgx_init_quote_ex)
            {
                OE_TRACE_ERROR(
                    "sgxquoteexprovider: sgx_init_quote_ex not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }
            library->sgx_get_quote_size_ex =
                dlsym(handle, SGX_GET_QUOTE_SIZE_NAME);
            if (!library->sgx_get_quote_size_ex)
            {
                OE_TRACE_ERROR(
                    "sgxquoteexprovider: sgx_get_quote_size_ex not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }
            library->sgx_get_quote_ex = dlsym(handle, SGX_GET_QUOTE_EX_NAME);
            if (!library->sgx_get_quote_ex)
            {
                OE_TRACE_ERROR(
                    "sgxquoteexprovider: sgx_get_quote_ex not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }
            library->sgx_get_supported_att_key_id_num =
                dlsym(handle, SGX_GET_SUPPORTED_ATT_KEY_ID_NUM_NAME);
            if (!library->sgx_get_supported_att_key_id_num)
            {
                OE_TRACE_ERROR("sgxquoteexprovider: "
                               "sgx_get_supported_att_key_id_num not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }
            library->sgx_get_supported_att_key_ids =
                dlsym(handle, SGX_GET_SUPPORTED_ATT_KEY_IDS_NAME);
            if (!library->sgx_get_supported_att_key_ids)
            {
                OE_TRACE_ERROR("sgxquoteexprovider: "
                               "sgx_get_supported_att_key_ids not fuond\n");
                OE_RAISE(OE_PLATFORM_ERROR);
            }

            atexit(_unload_quote_ex_library);

            library->handle = handle;
            result = OE_OK;
        }
        else
        {
            OE_TRACE_ERROR(
                "sgxquoteexprovider: failed to load %s: %s\n",
                _quote_ex_library_file_name,
                dlerror());

            library->handle = 0;
            result = OE_NOT_FOUND;
        }
    }

done:
    library->load_result = result;
    if (result != OE_OK)
        _unload_quote_ex_library();
}
