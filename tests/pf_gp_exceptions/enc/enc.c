// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "pf_gp_exceptions_t.h"

#define MOV_INSTRUCTION_BYTES 3
#define LGDT_INSTRUCTION_BYTES 8

static uint64_t faulting_address;
static uint32_t error_code;
static uint32_t exception_code;
static uint64_t bypass_bytes;

uint64_t test_pfgp_handler(oe_exception_record_t* exception_record)
{
    if (exception_record->code == OE_EXCEPTION_PAGE_FAULT)
    {
        faulting_address = exception_record->faulting_address;
        error_code = exception_record->error_code;
        exception_record->context->rip += bypass_bytes;
        exception_code = OE_EXCEPTION_PAGE_FAULT;
    }
    else if (exception_record->code == OE_EXCEPTION_ACCESS_VIOLATION)
    {
        faulting_address = exception_record->faulting_address;
        error_code = exception_record->error_code;
        exception_record->context->rip += bypass_bytes;
        exception_code = OE_EXCEPTION_ACCESS_VIOLATION;
    }
    else
        return OE_EXCEPTION_ABORT_EXECUTION;

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
    bypass_bytes = MOV_INSTRUCTION_BYTES;
    asm volatile("mov $8, %%r8\n\t"
                 "mov (%%r8), %%r8" ::
                     : "r8");
    OE_TEST(faulting_address == 8);
    OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);

    /* Trigger #GP */
    faulting_address = 1;
    bypass_bytes = LGDT_INSTRUCTION_BYTES;
    asm volatile("lgdt 0x00");
    /* faulting_address should be cleared */
    OE_TEST(faulting_address == 0);
    OE_TEST(exception_code == OE_EXCEPTION_ACCESS_VIOLATION);

    return 0;
}

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    ({0}), /* ExtendedProductID */
    ({0}), /* FamilyID */
    true,  /* Debug */
    true,  /* CapturePFGPExceptions */
    false, /* RequireKSS */
    false, /* CreateZeroBaseEnclave */
    0,     /* StartAddress */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    1);    /* NumTCS */
