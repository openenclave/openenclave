// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/tests.h>
#include <openenclave/log.h>

#include <execinfo.h>
#include <stdio.h>
#include <string.h>

#include "backtrace_t.h"

#define MOV_INSTRUCTION_BYTES 7
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
            &r,
            oe_get_enclave(),
            OE_LOG_LEVEL_INFO,
            (uint64_t*)buffer,
            (size_t)size) == OE_OK);
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

OE_NEVER_INLINE
static void _trigger_segfault()
{
    uint64_t code_page = (uint64_t)_trigger_segfault;

    /* Trigger segfault by writing to the code page */
    asm volatile("mov $1, %0" : "=r"(*(uint64_t*)code_page));
}

void enc_test_segfault()
{
    _trigger_segfault();
}

static uint64_t _segfault_handler(oe_exception_record_t* exception_record)
{
    if (exception_record->code != OE_EXCEPTION_PAGE_FAULT)
        return OE_EXCEPTION_ABORT_EXECUTION;

    /* Bypass the faulting instruction */
    exception_record->context->rip += MOV_INSTRUCTION_BYTES;

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

void enc_test_abort_after_segfault()
{
    OE_EXPECT(
        oe_add_vectored_exception_handler(false, _segfault_handler), OE_OK);

    _trigger_segfault();

    test_print_abort_backtrace();
}
