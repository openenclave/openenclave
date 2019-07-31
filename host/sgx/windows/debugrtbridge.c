// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/trace.h>
#include <stdlib.h>
#include "../../hostthread.h"

static struct
{
    oe_once_type once;
    HMODULE hmodule;
    oe_result_t (*notify_enclave_created)(oe_debug_enclave_t* enclave);
    oe_result_t (*notify_enclave_terminated)(oe_debug_enclave_t* enclave);
    oe_result_t (*push_thread_binding)(
        oe_debug_enclave_t* enclave,
        struct _sgx_tcs* tcs);
    oe_result_t (*pop_thread_binding)(void);
} _oedebugrt;

static void get_debugrt_function(const char* name, FARPROC* out)
{
    *out = GetProcAddress(_oedebugrt.hmodule, name);
    if (*out == NULL)
    {
        OE_TRACE_FATAL("Could not find function %s in oedebugrt.dll", name);
    }
}

static void load_oedebugrt(void)
{
    if (_oedebugrt.hmodule != NULL)
    {
        OE_TRACE_WARNING("oedebugrt.dll has already been loaded.");
        return;
    }

#ifndef NDEBUG
    /**
     *  In debug mode, give preference to OE_DEBUGRT_PATH.
     *  This is mainly used for OE SDK development.
     */
    {
        char* debugrtpath = getenv("OE_DEBUGRT_PATH");
        _oedebugrt.hmodule = LoadLibraryExA(
            debugrtpath,
            NULL, /* reserved */
            /* Search only specified path. */
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    }

#endif

    /* Search for oedebugrt.dll only in the application folder. */
    if (_oedebugrt.hmodule == NULL)
    {
        _oedebugrt.hmodule = LoadLibraryExA(
            "oedebugrt.dll",
            NULL, /* reserved */
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    }

    if (_oedebugrt.hmodule != NULL)
    {
        get_debugrt_function(
            "oe_debug_notify_enclave_created",
            (FARPROC*)&_oedebugrt.notify_enclave_created);
        get_debugrt_function(
            "oe_debug_notify_enclave_terminated",
            (FARPROC*)&_oedebugrt.notify_enclave_terminated);
        get_debugrt_function(
            "oe_debug_push_thread_binding",
            (FARPROC*)&_oedebugrt.push_thread_binding);
        get_debugrt_function(
            "oe_debug_pop_thread_binding",
            (FARPROC*)&_oedebugrt.pop_thread_binding);

        OE_TRACE_INFO(
            "oedebugrtbridge: Loaded oedebugrt.dll. Debugging is available.\n");
    }
    else
    {
        DWORD error = GetLastError();
        OE_TRACE_INFO(
            "oedebugrtbridge: LoadLibraryEx on oedebugrt.dll error"
            "= %#x. Debugging is unavailable.\n",
            error);
    }
}

static void cleanup(void)
{
    if (_oedebugrt.hmodule != NULL)
    {
        FreeLibrary(_oedebugrt.hmodule);
    }
}

static void initialize()
{
    oe_once(&_oedebugrt.once, &load_oedebugrt);
    atexit(&cleanup);
}

oe_result_t oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave)
{
    if (_oedebugrt.notify_enclave_created)
        return _oedebugrt.notify_enclave_created(enclave);

    return OE_OK;
}

oe_result_t oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave)
{
    if (_oedebugrt.notify_enclave_terminated)
        return _oedebugrt.notify_enclave_terminated(enclave);

    return OE_OK;
}

oe_result_t oe_debug_push_thread_binding(
    oe_debug_enclave_t* enclave,
    struct _sgx_tcs* tcs)
{
    if (_oedebugrt.push_thread_binding)
        return _oedebugrt.push_thread_binding(enclave, tcs);

    return OE_OK;
}

oe_result_t oe_debug_pop_thread_binding()
{
    if (_oedebugrt.pop_thread_binding)
        return _oedebugrt.pop_thread_binding();

    return OE_OK;
}
