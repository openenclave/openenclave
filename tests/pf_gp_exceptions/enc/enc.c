// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "pf_gp_exceptions_t.h"

#define MOV_INSTRUCTION_BYTES 3
#define LGDT_INSTRUCTION_BYTES 8

bool is_enclave_debug_allowed();

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
    {
        /* Unexpected code */
        oe_abort();
    }

    return OE_EXCEPTION_CONTINUE_EXECUTION;
}

int enc_pf_gp_exceptions(int is_misc_region_supported)
{
    /* Do nothing if we are in the debug mode with SGX1 */
    if (!is_misc_region_supported && !is_enclave_debug_allowed())
    {
        oe_host_printf("Test is bypassed with SGX1 non-debug mode\n");
        return 0;
    }

    if (oe_add_vectored_exception_handler(false, test_pfgp_handler) != OE_OK)
        return -1;

    /* Trigger #PF by writing to a read-only enclave code page.
     * The faulting address within enclave memory range will always have
     * lower 12 bits cleared on both non-simulation (SGX2) and simulation (SGX1)
     * mode. */
    faulting_address = 0;
    bypass_bytes = MOV_INSTRUCTION_BYTES;
    uint64_t code_page = (uint64_t)enc_pf_gp_exceptions;
    const uint64_t page_size = 0x1000;
    code_page = (code_page + (page_size - 1)) & ~(page_size - 1);

    asm volatile("mov %0, %%r8\n\t"
                 "mov %%r8, (%%r8)"
                 :
                 : "r"(code_page));
    if (is_misc_region_supported)
    {
        OE_TEST(faulting_address == code_page);
        OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);
    }
    else
    {
        /* faulting_address is passed in by the host */
        OE_TEST(faulting_address == code_page);
        OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);
        OE_TEST(error_code == OE_SGX_PAGE_FAULT_US_FLAG);
    }
    oe_host_printf("Test #PF on 0x%lx passed\n", faulting_address);

    /* Trigger #PF by reading to an unmapped address on the host.
     * The faulting address on the host memory will not have lower 12-bits
     * cleared in non-simulation case (SGX2). For the simulation mode (SGX1),
     * the faulting address will always be page-aligned. */
    faulting_address = 0;
    bypass_bytes = MOV_INSTRUCTION_BYTES;
    uint64_t unmapped_address = 0x1001;
    uint64_t unmapped_address_aligned = unmapped_address & ~(page_size - 1);

    asm volatile("mov %0, %%r8\n\t"
                 "mov (%%r8), %%r8"
                 :
                 : "r"(unmapped_address));
    if (is_misc_region_supported)
    {
        /* Expect the address without lower 12-bits cleared */
        OE_TEST(faulting_address == unmapped_address);
        OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);
    }
    else
    {
        /* faulting_address is passed in by the host, always page-aligned */
        OE_TEST(faulting_address == unmapped_address_aligned);
        OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);
        OE_TEST(error_code == OE_SGX_PAGE_FAULT_US_FLAG);
    }
    oe_host_printf("Test #PF on 0x%lx passed\n", unmapped_address);

    /* Trigger #GP */
    faulting_address = 1;
    bypass_bytes = LGDT_INSTRUCTION_BYTES;
    asm volatile("lgdt 0x00");
    if (is_misc_region_supported)
    {
        /* faulting_address should be cleared */
        OE_TEST(faulting_address == 0);
        OE_TEST(exception_code == OE_EXCEPTION_ACCESS_VIOLATION);
    }
    else
    {
        /* faulting_address is passed in by the host */
        OE_TEST(faulting_address == 0);
        /* On SGX1, simulating all the unsupported exception types
         * as #PF. */
        OE_TEST(exception_code == OE_EXCEPTION_PAGE_FAULT);
        OE_TEST(error_code == OE_SGX_PAGE_FAULT_US_FLAG);
    }
    oe_host_printf("Test #GP passed\n");

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
