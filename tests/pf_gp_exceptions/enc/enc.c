// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "pf_gp_exceptions_t.h"

static uint64_t faulting_address;
static uint32_t error_code;

uint64_t test_pfgp_handler(oe_exception_record_t* exception_record)
{
    if (exception_record->code == OE_EXCEPTION_PAGE_FAULT)
    {
        const int MOV_INSTRUCTION_BYTES = 3;
        faulting_address = exception_record->faulting_address;
        error_code = exception_record->error_code;
        exception_record->context->rip += MOV_INSTRUCTION_BYTES;
        oe_host_printf(
            "#PF: addr: 0x%lx, code: %u\n",
            exception_record->faulting_address,
            exception_record->error_code);
    }
    else if (exception_record->code == OE_EXCEPTION_ACCESS_VIOLATION)
    {
        const int LGDT_INSTRUCTION_BYTES = 8;
        faulting_address = exception_record->faulting_address;
        error_code = exception_record->error_code;
        exception_record->context->rip += LGDT_INSTRUCTION_BYTES;
        oe_host_printf(
            "#GP: addr: 0x%lx, code: %u\n",
            exception_record->faulting_address,
            exception_record->error_code);
    }
    else
    {
        oe_host_printf("Unhandled code: %u\n", exception_record->code);
        oe_abort();
    }

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

int enc_pf_gp_exceptions()
{
    oe_result_t result;

    result = oe_add_vectored_exception_handler(false, test_pfgp_handler);
    if (result != OE_OK)
    {
        return -1;
    }

    /* Trigger #PF */
    faulting_address = 1;
    asm volatile("xor %rax, %rax\n\t"
                 "mov (%rax), %rax");
    OE_TEST(faulting_address == 0);

    /* Trigger #GP */
    faulting_address = 1;
    asm volatile("lgdt 0x00");
    OE_TEST(faulting_address == 0);

    return 0;
}

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    {0},   /* ExtendedProductID */
    {0},   /* FamilyID */
    true,  /* Debug */
    true,  /* CapturePFGPExceptions */
    false, /* RequireKSS */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    1);    /* NumTCS */
