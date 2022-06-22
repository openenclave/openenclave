// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>

#include <execinfo.h>
#include <stdio.h>
#include <string.h>

#include "backtrace_t.h"

#define NUM_FRAMES (32)

OE_NEVER_INLINE
void test_print_backtrace()
{
    oe_result_t r;
    void* buffer[NUM_FRAMES];

    int size = backtrace(buffer, NUM_FRAMES);
    OE_TEST(size > 0 && size <= NUM_FRAMES);

    OE_TEST(
        oe_sgx_log_backtrace_ocall(
            &r, oe_get_enclave(), (uint64_t*)buffer, (size_t)size) == OE_OK);
    OE_TEST(r == OE_OK);
}

OE_NEVER_INLINE
void test_print_abort_backtrace()
{
    oe_abort();
    printf("This call exists to prevent a tail call (jump) to oe_abort");
}

void enc_test()
{
    test_print_backtrace();
    test_print_abort_backtrace();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
