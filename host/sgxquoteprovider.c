// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#if defined(__linux__)

#include <dlfcn.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>

#include "hostthread.h"
#include "sgxquoteprovider.h"

/**
 * This file manages the libngsa_quoteprov.so shared library.
 * It loads the .so during program startup and keeps it loaded till application
 * exit. Intel's quoting library repeatedly loads and unlods
 * libngsa_quoteprov.so.
 * This causes a crash in libssl.so. (See
 * https://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=2325).
 * Keeping libngsa_quoteprov.so pinned in memory solves the libssl.so crash.
 */

static void* g_LibHandle = 0;

static void _UnloadQuoteProvider()
{
    if (g_LibHandle)
    {
        dlclose(g_LibHandle);
        g_LibHandle = 0;
    }
}

static void _QuoteProviderLog(int level, const char* message)
{
    const char* levelString = level == 0 ? "ERROR" : "INFO";
    char formatted[1024];

    snprintf(formatted, sizeof(formatted), "[%s]: %s\n", levelString, message);

    formatted[sizeof(formatted) - 1] = 0;

    printf("%s", formatted);
}

typedef void (*log_fcn_t)(int, const char*);
typedef void (*set_logging_fcn_t)(log_fcn_t);

static void _LoadQuoteProvider()
{
    if (g_LibHandle == 0)
    {
        g_LibHandle = dlopen("libngsa_quoteprov.so", RTLD_LAZY | RTLD_LOCAL);
        if (g_LibHandle != 0)
        {
            set_logging_fcn_t set_log_fcn = (set_logging_fcn_t)dlsym(
                g_LibHandle, "sgx_ql_set_logging_function");
            if (set_log_fcn != NULL)
            {
                OE_UNUSED(_QuoteProviderLog);

                OE_TRACE_INFO("sgxquoteprovider: Installed log function\n");
#if (OE_TRACE_LEVEL >= OE_TRACE_LEVEL_INFO)
                // If info tracing is enabled, install the logging function.
                set_log_fcn(_QuoteProviderLog);
#endif
            }
            else
            {
                OE_TRACE_INFO(
                    "sgxquoteprovider: sgx_ql_set_logging_function "
                    "not found\n");
            }
            atexit(_UnloadQuoteProvider);
        }
        else
        {
            OE_TRACE_INFO(
                "sgxquoteprovider: libngsa_quoteprov.so not found \n");
        }
    }
}

OE_Result OE_InitializeQuoteProvider()
{
    static OE_H_OnceType once = OE_H_ONCE_INITIALIZER;
    OE_H_Once(&once, _LoadQuoteProvider);
    return g_LibHandle ? OE_OK : OE_FAILURE;
}

#else

#include "sgxquoteprovider.h"

OE_Result OE_InitializeQuoteProvider()
{
    return OE_UNIMPLEMENTED;
}

#endif
