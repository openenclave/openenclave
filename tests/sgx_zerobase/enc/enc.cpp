// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <iostream>

#include "sgx_zerobase_t.h"

static uint64_t faulting_address = sizeof(uint64_t) - 1;
static uint32_t error_code;
static uint32_t exception_code;

uint64_t test_pfgp_handler(oe_exception_record_t* exception_record)
{
    if (exception_record->code == OE_EXCEPTION_PAGE_FAULT)
    {
        const int MOV_INSTRUCTION_BYTES = 3;
        faulting_address = exception_record->faulting_address;
        error_code = exception_record->error_code;
        exception_record->context->rip += MOV_INSTRUCTION_BYTES;
        exception_code = OE_EXCEPTION_PAGE_FAULT;
    }
    else
    {
        /* Unexpected code */
        oe_abort();
    }

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

int test_enclave_memory_access(uint64_t address, bool* exception)
{
    oe_result_t result = OE_OK;
    static int once = 0;

    if (exception && !once)
    {
        /* A handler should be declared only once per program execution */
        result = oe_add_vectored_exception_handler(false, test_pfgp_handler);
        once++;
    }

    if (result != OE_OK)
    {
        return -1;
    }

    /* Assign value to memory address 'address'*/
    asm volatile("mov (%0), %0\n\t" : : "r"(address) : "memory");

    if (exception)
    {
        if (faulting_address == address)
        {
            *exception = true;
        }
        else
            *exception = false;
    }

    return 0;
}

int test_ecall(const char* message)
{
    if (!message)
        return -1;
    else
        fprintf(stdout, "[enclave] Message from host : %s\n", message);

    int res = -1;
    const char* input = "testing ocall\0";
    OE_TEST(test_ocall(&res, input) == OE_OK);
    if (res != 0)
        fprintf(stderr, "[enclave] ocall failed %d\n", res);

    return res;
}

OE_SET_ENCLAVE_SGX2(
    1,       /* ProductID */
    1,       /* SecurityVersion */
    {0},     /* ExtendedProductID */
    {0},     /* FamilyID */
    true,    /* Debug */
    true,    /* CapturePFGPExceptions */
    false,   /* RequireKSS */
    true,    /* CreateZeroBaseEnclave */
    0x21000, /* StartAddress */
    1024,    /* NumHeapPages */
    1024,    /* NumStackPages */
    4);      /* NumTCS */
