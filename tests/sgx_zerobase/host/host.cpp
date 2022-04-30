// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/exception.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <sys/mman.h>
#include <iostream>

#include "../host/sgx/cpuid.h"
#include "sgx_zerobase_u.h"

#define SKIP_RETURN_CODE 2

const char* message = "Hello world from Host\n\0";

static bool _is_misc_region_supported()
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(CPUID_SGX_LEAF, 0x0, &eax, &ebx, &ecx, &edx);

    // Check if EXINFO is supported by the processor
    return (ebx & CPUID_SGX_MISC_EXINFO_MASK);
}

int test_ocall(const char* message)
{
    if (!message)
        return -1;

    fprintf(stdout, "[host] Message from enclave : %s\n", message);

    return 0;
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

    if (!oe_sgx_has_quote_provider())
    {
        // this test should not run on any platforms where FLC is not supported
        OE_TRACE_INFO("=== tests skipped when DCAP libraries are not found.\n");
        return SKIP_RETURN_CODE;
    }

    if (strstr(argv[1], "_conf_") == NULL)
    {
        fprintf(
            stdout,
            "\nTest 1: Create 0-base enclave in sim-mode\n"
            "Expected result : OE_INVALID_PARAMETER\n");
        result = oe_create_sgx_zerobase_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            OE_ENCLAVE_FLAG_SIMULATE,
            NULL,
            0,
            &enclave);

        if (result != OE_INVALID_PARAMETER)
        {
            fprintf(
                stderr,
                "Unexpected error when creating enclave in sim-mode,"
                " result=%d\n",
                result);
            return 1;
        }
    }

    const uint32_t flags = oe_get_create_flags();

    /*
     * 0-base enclaves are not supported in sim-mode.
     */
    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
    {
        fprintf(stdout, "Simulation mode does not support 0-base enclaves.\n");
        return 0;
    }

    fprintf(
        stdout,
        "\nTest 2: Create 0-base enclave\n"
        "Expected result : OE_OK\n");

    result = oe_create_sgx_zerobase_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create 0-base enclave, result=%d\n", result);
        return 1;
    }

    fprintf(
        stdout,
        "\nTest 3: Test ecall, ocall on 0-base enclave\n"
        "Expected result : OE_OK\n");

    const char* input = argv[1];
    int res = -1;

    OE_TEST(test_ecall(enclave, &res, input) == OE_OK);

    if (res != 0)
    {
        fprintf(stderr, "[host]: ecall/ocall failed %d\n", res);
        return 1;
    }

    if (strstr(argv[1], "_conf_disable_") != NULL)
    {
        fprintf(
            stdout,
            "Configuration file has disabled 0-base enclave creation."
            " Skipping 0-base memory tests for this enclave.\n");
        return 0;
    }

    fprintf(
        stdout,
        "\nTest 4: Check host access between /proc/sys/vm/mmap_min_addr and "
        "enclave image start address - [0x1000, 0x21000)\n"
        "Expected result : success\n");

    uint64_t address = 0x15000;

    if ((uint64_t)mmap(
            (void*)address,
            1,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0) != address)
    {
        fprintf(stderr, "host mmap at address 0x%lx failed\n", address);
        return 1;
    }

    /* Enclave memory access tests */
    if (_is_misc_region_supported())
    {
        bool exception = false;

        fprintf(
            stdout,
            "\nTest 5: memory access between start_address and elrange_end"
            " - [0x21000, 0x40000)\n"
            "Expected result: no exceptions\n");
        /*
         * elrange_end =
         * nearest_pow_2((start_address - base_address) + enclave_image_size)
         */
        address = 0x31000;
        exception = false; /* reset exception */

        result = test_enclave_memory_access(enclave, &res, address, &exception);
        if (res != 0)
        {
            fprintf(stderr, "test_enclave_memory_access failed %d\n", res);
            return 1;
        }

        fprintf(stdout, "address 0x%lx, page-fault %d\n", address, exception);
        if (exception)
            return 1;

        fprintf(
            stdout,
            "\nTest 6: Enclave memory access between /proc/sys/vm/mmap_min_addr"
            " and enclave image start address - [0x1000, 0x21000)\n"
            "Expected result: page-fault\n");

        address = 0x15000;
        exception = false; /* reset exception */

        result = test_enclave_memory_access(enclave, &res, address, &exception);
        if (res != 0)
        {
            fprintf(stderr, "test_enclave_memory_access failed %d\n", res);
            return 1;
        }

        fprintf(stdout, "address 0x%lx, page-fault %d\n", address, exception);
        if (!exception)
            return 1;
    }
    else
        fprintf(
            stdout,
            "\nCPU does not support the CapturePFGPExceptions=1 "
            "configuration.\n"
            "Cannot catch exceptions from enclave, "
            "skipping enclave memory access tests.\n");

    if (oe_terminate_enclave(enclave) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave(): failed: result=%d\n", result);
        return 1;
    }

    printf("\n=== passed all tests (sgx_zerobase)\n");

    return 0;
}
