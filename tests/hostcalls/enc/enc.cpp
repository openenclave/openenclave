// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "hostcalls_t.h"

void test_host_malloc(size_t in_size, void_ptr* out_ptr)
{
    *out_ptr = oe_host_malloc(in_size);
    if (*out_ptr && !oe_is_outside_enclave(*out_ptr, in_size))
    {
        oe_abort();
        return;
    }
}

void test_host_calloc(size_t in_num, size_t in_size, void_ptr* out_ptr)
{
    *out_ptr = oe_host_calloc(in_num, in_size);
    if (*out_ptr && !oe_is_outside_enclave(*out_ptr, in_size * in_num))
    {
        oe_abort();
        return;
    }
}

void test_host_realloc(
    void_ptr in_ptr,
    size_t old_size,
    size_t new_size,
    void_ptr* _out_ptr)
{
    /* Check that pointers passed in are not enclave pointers */
    if (in_ptr && old_size > 0)
    {
        if (!oe_is_outside_enclave(in_ptr, old_size))
        {
            oe_abort();
            return;
        }
    }

    void_ptr out_ptr = oe_host_realloc(in_ptr, new_size);

    /* Initialize only newly allocated bytes for verification by host */
    if (out_ptr)
    {
        if (!in_ptr)
        {
            memset(out_ptr, TEST_HOSTREALLOC_INIT_VALUE, new_size);
        }
        else if (old_size < new_size)
        {
            void* ext_ptr = (void*)((uint64_t)out_ptr + old_size);
            memset(ext_ptr, TEST_HOSTREALLOC_INIT_VALUE, new_size - old_size);
        }
    }

    *_out_ptr = out_ptr;
}

void test_host_strndup(const char* in_str, size_t in_size, char** out_str)
{
    *out_str = oe_host_strndup(in_str, in_size);
}

void test_host_free(void_ptr in_ptr)
{
    oe_host_free(in_ptr);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    128,  /* NumStackPages */
    16);  /* NumTCS */

#define TA_UUID                                            \
    { /* 60814a64-61e9-4fd9-9159-e158d73f6a2e */           \
        0x60814a64, 0x61e9, 0x4fd9,                        \
        {                                                  \
            0x91, 0x59, 0xe1, 0x58, 0xd7, 0x3f, 0x6a, 0x2e \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Host Calls test")
