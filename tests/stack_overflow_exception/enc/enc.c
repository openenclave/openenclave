// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include "stack_overflow_exception_t.h"

#define PAGE_SIZE 4096
#define EXCEPTION_HANDLER_STACK_SIZE 8192
#define STACK_PAGE_NUMBER 2
#define STACK_SIZE (STACK_PAGE_NUMER * PAGE_SIZE)
bool oe_sgx_set_td_exception_handler_stack(void* stack, uint64_t size);
void* td_to_tcs(const oe_sgx_td_t* td);

uint8_t exception_handler_stack[EXCEPTION_HANDLER_STACK_SIZE];

uint64_t test_stack_overflow_handler(oe_exception_record_t* exception_record)
{
    OE_TEST(exception_record->code == OE_EXCEPTION_PAGE_FAULT);

    /* Calculate the stack boundary based on OE enclave memory layout */
    oe_sgx_td_t* td = oe_sgx_get_td();
    void* tcs = td_to_tcs(td);
    uint64_t stack_base = (uint64_t)tcs - PAGE_SIZE;
    OE_TEST(exception_record->context->rsp < (stack_base - STACK_PAGE_NUMBER));

    host_notify_stack_overflowed();

    return OE_EXCEPTION_ABORT_EXECUTION;
}

oe_result_t enc_initialize_exception_handler()
{
    oe_result_t result = OE_FAILURE;

    if (!oe_sgx_set_td_exception_handler_stack(
            exception_handler_stack, EXCEPTION_HANDLER_STACK_SIZE))
        goto done;

    OE_CHECK(
        oe_add_vectored_exception_handler(false, test_stack_overflow_handler));

    result = OE_OK;

done:
    return result;
}

void enc_stack_overflow_exception()
{
    uint8_t data[1024];

    // Force stack allocation and do the recursive call untill
    // the stack overflows
    asm volatile("leaq %0, %%r8\n\t"
                 "movw $1, 1023(%%r8)\n\t"
                 "call enc_stack_overflow_exception\n\t"
                 :
                 : "m"(data)
                 : "r8");
}

OE_SET_ENCLAVE_SGX2(
    1,                 /* ProductID */
    1,                 /* SecurityVersion */
    ({0}),             /* ExtendedProductID */
    ({0}),             /* FamilyID */
    true,              /* Debug */
    true,              /* CapturePFGPExceptions */
    false,             /* RequireKSS */
    false,             /* CreateZeroBaseEnclave */
    0,                 /* StartAddress */
    1024,              /* NumHeapPages */
    STACK_PAGE_NUMBER, /* NumStackPages */
    1);                /* NumTCS */
