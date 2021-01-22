// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <host/ecall_ids.h>
#include <host/hostthread.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/tests.h>
#include <cmath>
#include "../abi_utils.h"
#include "abi_u.h"

extern "C"
{
#include <host/sgx/enclave.h>
}

#include <openenclave/internal/constants_x64.h>

#ifdef _WIN32
extern "C"
{
    void oe_dummy_mmx_add();
    void oe_dummy_fpu_loads();
}
#endif

oe_result_t test_abi_roundtrip(oe_enclave_t* enclave)
{
    printf("=== test_abi_roundtrip()\n");

    oe_result_t result = OE_UNEXPECTED;
    abi_state_t before_ecall_state = {};
    abi_state_t after_ecall_state = {};

    uint64_t global_id = OE_GLOBAL_ECALL_ID_NULL;
    oe_thread_key thread_binding_key;

    /* Test invariant: abi_enc is defined with only a single thread */
    oe_thread_binding_t* binding = &enclave->bindings[0];
    void* tcs = (void*)binding->tcs;

    /* Marshalling struct cloned from abi_u.c, needs to be at least 16-bytes */
    typedef struct _enclave_check_abi_args_t
    {
        oe_result_t _result;
        void* deepcopy_out_buffer;
        size_t deepcopy_out_buffer_size;
        double _retval;
    } enclave_check_abi_args_t;

    /* Helper struct definition to manually flatten out ecall buffer with
     * standard ecall parameters and args for enclave_check_abi. This test
     * unrolls the EDL generated call stubs so that it can directly invoke
     * the oe_enter directly to check its ABI handling */
    typedef struct _flat_ecall_args
    {
        oe_call_enclave_function_args_t enc_function_args;
        enclave_check_abi_args_t check_abi_args;
    } flat_ecall_args_t;

    flat_ecall_args_t* args = NULL;

    const flat_ecall_args_t args_template = {
        {.function_id = 0,
         .input_buffer = NULL,
         .input_buffer_size = sizeof(args_template.check_abi_args),
         .output_buffer = NULL,
         .output_buffer_size = sizeof(args_template.check_abi_args),
         .output_bytes_written = 0,
         .result = OE_UNEXPECTED},
        {._result = OE_UNEXPECTED,
         .deepcopy_out_buffer = NULL,
         .deepcopy_out_buffer_size = 0,
         ._retval = 0}};

    /* Skip the ABI state test in simulation mode since OE SDK doesn't
     * provide special ABI handling on simulated enclave transition */
    if (enclave->simulate)
        OE_RAISE_MSG(
            OE_UNSUPPORTED,
            "SKIPPING in test_abi_roundtrip() in Simulation Mode\n",
            NULL);

    /* Alloc and initialize the enclave_check_abi ECALL args buffer */
    args = (flat_ecall_args_t*)malloc(sizeof(args_template));
    if (!args)
        OE_RAISE(OE_OUT_OF_MEMORY);

    memcpy(args, &args_template, sizeof(args_template));
    args->enc_function_args.input_buffer = &args->check_abi_args;
    args->enc_function_args.output_buffer = &args->check_abi_args;
    OE_CHECK(oe_get_ecall_ids(
        enclave,
        "enclave_check_abi",
        &global_id,
        &args->enc_function_args.function_id));

    /* This method needs to perform its own thread binding since it doesn't
     * call through oe_ecall to get at oe_enter directly, and oe_ecall is
     * responsible for the thread binding in the normal code path. */
    if (binding->flags & _OE_THREAD_BUSY)
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "ASSERT: test_abi_roundtrip() expects to be single threaded with "
            "access to the only enclave thread context, but the thread binding "
            "at index 0 is marked BUSY\n",
            NULL);

    /* This test asserts the invariant as a single threaded app that
     * test_abi_roundtrip runs right after enclave initialization, which set
     * the thread_binding_key for ecalls already. This oe_thread_key_create
     * value called here should then return the next thread local storage index,
     * so to infer the one used for ecalls we use the obtained value - 1 */
    if (!oe_thread_key_create(&thread_binding_key))
    {
        /* The key index (the reservation of the slot) can be freed immediately
         * since the thread storage itself is not used by this test */
        oe_thread_key_delete(thread_binding_key);
    }
    else
        OE_RAISE_MSG(OE_UNEXPECTED, "oe_thread_key_create failed\n", NULL);

    oe_thread_setspecific(thread_binding_key - 1, binding);
    binding->flags |= _OE_THREAD_BUSY;
    binding->thread = oe_thread_self();
    binding->count = 1;

    /* Notify the debugger runtime */
    if (enclave->debug && enclave->debug_enclave != NULL)
        oe_debug_push_thread_binding(enclave->debug_enclave, (sgx_tcs_t*)tcs);

    /* Emulate the oe_ecall flow */
    {
        uint64_t arg1 = oe_make_call_arg1(
            OE_CODE_ECALL, OE_ECALL_CALL_ENCLAVE_FUNCTION, 0, OE_OK);
        uint64_t arg2 = (uint64_t)args;
        uint64_t arg3 = 0;
        uint64_t arg4 = 0;

        /* Set up and cache ABI test state */
        set_test_xmm_state();
        set_test_abi_state();
        read_abi_state(&before_ecall_state);

        /* Invoke oe_enter directly to test the ocall transition ABI handling */
        oe_enter(tcs, OE_AEP_ADDRESS, arg1, arg2, &arg3, &arg4, enclave);

        /* Snap the ABI state immediately on return and clear test changes */
        read_abi_state(&after_ecall_state);
        reset_test_abi_state();

        oe_code_t code_out = oe_get_code_from_call_arg1(arg3);
        uint16_t result_out = oe_get_result_from_call_arg1(arg3);

        /* Check that the exit is not from unexpected OCALL, which should
         * have been handled within oe_enter already */
        if (code_out != OE_CODE_ERET)
            OE_RAISE_MSG(
                OE_UNEXPECTED,
                "test_abi_roundtrip only expects ERET but received an "
                "unexpected EEXIT code: %#x\n",
                code_out);

        /* Check that the ECALL succeeded */
        OE_CHECK((oe_result_t)result_out);
    }

    /* Check the enclave_check_abi function succeeded and produced output */
    OE_CHECK(args->enc_function_args.result);
    if (args->enc_function_args.output_bytes_written !=
        sizeof(args_template.check_abi_args))
        OE_RAISE_MSG(
            OE_UNEXPECTED,
            "enclave_check_abi only wrote %#x output bytes\n",
            args->enc_function_args.output_bytes_written);

    /* Check the enclave_check_abi function returned expected value */
    if (args->check_abi_args._retval != EXPECTED_CHECK_ABI_RETURN_VALUE)
        OE_RAISE_MSG(
            OE_FAILURE,
            "enclave_check_abi returned %f instead of expected value set by "
            "host_check_abi\n",
            args->check_abi_args._retval);

    /* Verify that the expected ABI is preserved */
    if (!is_same_abi_state(&before_ecall_state, &after_ecall_state))
        OE_RAISE_MSG(
            OE_FAILURE,
            "ABI state before and after oe_enter were not equal\n",
            NULL);

    result = OE_OK;

done:
    /* Clean up the thread binding and debugger registration */
    if (binding->flags & _OE_THREAD_BUSY)
    {
        binding->count--;

        /* Notify the debugger runtime */
        if (enclave->debug && enclave->debug_enclave != NULL)
            oe_debug_pop_thread_binding();

        if (binding->count == 0)
        {
            binding->flags &= (~_OE_THREAD_BUSY);
            binding->thread = 0;
            memset(&binding->event, 0, sizeof(binding->event));
            oe_thread_setspecific(thread_binding_key - 1, NULL);
        }
    }

    return result;
}

double host_check_abi()
{
    return EXPECTED_CHECK_ABI_RETURN_VALUE;
}

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

    // oe_is_avx_enabled has already been setup by the host runtime.
    // Pass it along to the enclave.
    OE_TEST(enclave_set_oe_is_avx_enabled(enclave, oe_is_avx_enabled) == OE_OK);

    result = test_abi_roundtrip(enclave);
    OE_TEST(result == OE_OK || result == OE_UNSUPPORTED);

    test_mmx_abi_poison(enclave);
    test_fpu_stack_overflow(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
