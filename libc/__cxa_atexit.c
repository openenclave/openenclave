// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/cxa_atexit.h>

/*
 * Registers a function to be called by exit and by oe_call_atexit.
 * This function wraps oe_cxa_atexit, which ignores dso_handle.
 */
int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    return oe_cxa_atexit(func, arg, dso_handle);
}
