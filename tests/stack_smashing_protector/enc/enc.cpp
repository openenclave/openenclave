// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <stdio.h>
#include "ssp_t.h"

static oe_once_t g_once = OE_ONCE_INIT;
static oe_thread_key_t g_key = OE_THREADKEY_INITIALIZER;

static bool g_destructor_called = false;

static void _destructor(void* data)
{
    char* str = (char*)data;

    if (oe_strcmp(str, "TSD-DATA") == 0)
    {
        oe_host_free(str);
        g_destructor_called = true;
        OE_TEST(oe_thread_setspecific(g_key, NULL) == 0);
    }
}

static void _init()
{
    if (oe_thread_key_create(&g_key, _destructor) != 0)
    {
        oe_abort();
    }
}
int enc_set_thread_variable(void* value)
{
    int rval = 0;
    /* Initialize this the first time */
    if (oe_once(&g_once, _init) != 0 ||
        oe_thread_setspecific(g_key, value) != 0)
    {
        rval = -1;
    }
    return rval;
}

void* enc_get_thread_specific_data()
{
    return oe_thread_getspecific(g_key);
}

bool was_destructor_called()
{
    return g_destructor_called;
}

void* ssp_test_sub()
{
    /* The test should change the canary in the current stack.
     * But in Debug mode the canary is at $rbp-0x8, and in Release mode
     * the canary is at $rsp+0x20. To avoid unseen cases, here the %%fs:0x28 is
     * modified.
     */
    uint64_t canary;
    asm("mov %%fs:0x28, %0" : "=r"(canary));
    canary /= 2;
    asm("mov %0, %%fs:0x28" : : "r"(canary));

    return 0;
}

void* ssp_test()
{
    ssp_test_sub();
    return (void*)0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    128,  /* NumStackPages */
    16);  /* NumTCS */
