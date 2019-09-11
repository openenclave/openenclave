// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../enclave/core/atexit.h"

/*
 * Registers a function to be called by exit and by oe_call_atexit. This
 * function is used to implement atexit, which calls __cxa_atexit with the
 * following arguments: __cxa_atexit(func, NULL, NULL)
 */
int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    return oe_cxa_atexit(func, arg, dso_handle);
}
