// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cmath>

#include "abi_u.h"

#ifdef _WIN32
extern "C"
{
    void oe_dummy_mmx_add();
    void oe_dummy_fpu_loads();
}
#endif

OE_NO_OPTIMIZE_BEGIN
void test_mmx_abi_poison(oe_enclave_t* enclave)
{
    double float_result = 0;
    uint64_t dummy = 0;

    printf("=== test_mmx_abi_poison()\n");

#ifdef _WIN32
    oe_dummy_mmx_add();
#else
    asm("movq %0, %%mm0\n\t"
        "paddd %%mm0, %%mm0\n\t" ::"m"(dummy)
        :);
#endif

    OE_TEST(enclave_add_float(enclave, &float_result) == OE_OK);

    printf("x87 FPU result = %f\n", float_result);
    OE_TEST(!std::isnan(float_result));
}

void test_fpu_stack_overflow(oe_enclave_t* enclave)
{
    double float_result = 0;
    uint64_t dummy = 0;

    printf("=== test_fpu_stack_overflow()\n");

#ifdef _WIN32
    oe_dummy_fpu_loads();
#else
    asm("fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t"
        "fldl %0\n\t" ::"m"(dummy)
        :);
#endif

    OE_TEST(enclave_add_float(enclave, &float_result) == OE_OK);

    printf("x87 FPU result = %f\n", float_result);
    OE_TEST(!std::isnan(float_result));
}
OE_NO_OPTIMIZE_END

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_abi_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_abi_enclave(): result=%u", result);
    }

    test_mmx_abi_poison(enclave);
    test_fpu_stack_overflow(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
