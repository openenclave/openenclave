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
#include "ocall_t.h"

uint64_t enc_test2(uint64_t val)
{
    return val;
}

void enc_test4()
{
    unsigned char buffer[32];
    memset(buffer, 0xAA, sizeof(buffer));

    /* Call into host with enclave memory */
    if (OE_OK != host_func2(buffer))
    {
        oe_abort();
    }
}

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
int enc_set_tsd(void* value)
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

void* enc_get_tsd()
{
    return oe_thread_getspecific(g_key);
}

bool was_destructor_called()
{
    return g_destructor_called;
}

uint64_t enc_test_my_ocall()
{
    uint64_t ret_val;
    oe_result_t result = host_my_ocall(&ret_val, MY_OCALL_SEED);
    OE_TEST(OE_OK == result);

    /* Test low-level OCALL of illegal function number */
    {
        oe_result_t result = oe_ocall(0xffff, 0, NULL);
        OE_TEST(OE_NOT_FOUND == result);
    }

    return ret_val;
}

void enc_test_reentrancy()
{
    oe_result_t result = host_test_reentrancy();
    OE_TEST(OE_OK == result);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
