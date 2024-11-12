// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/thread.h>
#include <iostream>

#include "sgx_zerobase_t.h"

static uint64_t faulting_address = sizeof(uint64_t) - 1;
static uint32_t error_code;
static uint32_t exception_code;
static oe_once_t _exception_handler_init_once;

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

void _initialize_exception_handler(void)
{
    oe_result_t result;
    result = oe_add_vectored_exception_handler(false, test_pfgp_handler);
    OE_UNUSED(result);
}

int test_enclave_memory_access(uint64_t address, bool* exception)
{
    oe_result_t result = OE_OK;

    if (exception)
    {
        /* A handler should be added only once per program execution */
        oe_once(&_exception_handler_init_once, _initialize_exception_handler);
    }

    if (result != OE_OK)
    {
        return -1;
    }

    /* Read value from memory address 'address'*/
    asm volatile("mov (%0), %0\n\t" : : "r"(address) : "memory");

    if (exception)
    {
        if (faulting_address == address)
            *exception = true;
        else
            *exception = false;
    }

    return 0;
}

extern "C"
{
    const void* __oe_get_enclave_start_address(void);
    const void* __oe_get_enclave_base_address(void);
}

int test_ecall(const char* message)
{
    if (!message)
        return -1;
    else
        fprintf(stdout, "[enclave] Enclave path: %s\n", message);

    uint64_t start_address = (uint64_t)__oe_get_enclave_start_address();
    uint64_t base_address = (uint64_t)__oe_get_enclave_base_address();

    fprintf(
        stdout,
        "[enclave] testing start_address : 0x%lx and base_address : 0x%lx\n",
        start_address,
        base_address);

    if (strstr(message, "_conf_disable") != NULL || /* not a 0-base enclave */
        (start_address == 0x30000) || /* config file set start_address */
        (start_address ==
         0x21000)) /* OE_SET_ENCLAVE_SGX2 macro set start_address */
    {
        fprintf(
            stdout,
            "[enclave] start_address : 0x%lx is valid\n",
            start_address);
    }
    else
    {
        fprintf(
            stderr,
            "[enclave] start_address has to be either the value set by "
            "OE_SET_ENCLAVE_SGX2 or the value set by configuration file."
            " The start_address 0x%lx does not match both.\n",
            start_address);
        return -1;
    }

    if ((strstr(message, "_conf_disable") != NULL && base_address != 0x0) ||
        base_address == 0x0)
    {
        fprintf(
            stdout, "[enclave] base_address : 0x%lx is valid\n", base_address);
    }
    else
    {
        fprintf(
            stderr,
            "[enclave] base_address should be 0x0 for a 0-base enclave.\n");
        return -1;
    }

    int res = -1;
    const char* input = "testing ocall\0";
    OE_TEST(test_ocall(&res, input) == OE_OK);
    if (res != 0)
        fprintf(stderr, "[enclave] ocall failed %d\n", res);

    return res;
}
