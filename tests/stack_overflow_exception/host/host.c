// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "../host/sgx/cpuid.h"
#include "stack_overflow_exception_u.h"

static bool enclave_stack_overflowed = false;

static bool _is_misc_region_supported()
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(CPUID_SGX_LEAF, 0x0, &eax, &ebx, &ecx, &edx);

    // Check if EXINFO is supported by the processor
    return (ebx & CPUID_SGX_MISC_EXINFO_MASK);
}

void host_notify_stack_overflowed()
{
    enclave_stack_overflowed = true;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_stack_overflow_exception_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    /* The enclave creation should succeed on both SGX1 and SGX2 machines. */
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
        printf("Simulation mode does not support exceptions. Skip the test "
               "ECALL.\n");
    else if (_is_misc_region_supported())
    {
        if (enc_initialize_exception_handler(enclave, &result) != OE_OK)
            oe_put_err(
                "enc_initialize_exception_handler() failed: result=%u", result);
        OE_TEST(result == OE_OK);

        OE_TEST(enc_stack_overflow_exception(enclave) == OE_ENCLAVE_ABORTING);
        OE_TEST(enclave_stack_overflowed == true);

        result = oe_terminate_enclave(enclave);
#ifdef DEBUG_BUILD
        /* Expect OE_MEMORY_LEAK in the debug build (the debugmalloc is enabled)
         * because the oe_handle_call_enclave_function does not return and
         * therefore an internal buffer on the heap is not freed  */
        OE_TEST(result == OE_MEMORY_LEAK);
#else
        OE_TEST_CODE(result, OE_OK);
#endif
    }
    else
    {
        printf("CPU does not support the CapturePFGPExceptions=1 "
               "configuration. Skip the test ECALL.\n");

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }

    printf("=== passed all tests (stack_overflow_exception)\n");

    return 0;
}
