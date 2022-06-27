// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <math.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/calls.h>
#include <stdlib.h>
#include <string.h>
#include "../abi_utils.h"
#include "abi_t.h"

OE_EXTERNC_BEGIN
// By default, assume avx is available. This is the case with most processors
// with SGX support.
bool oe_is_avx_enabled = true;
OE_EXTERNC_END

void enclave_set_oe_is_avx_enabled(bool enabled)
{
    oe_is_avx_enabled = enabled;
}

double enclave_add_float()
{
    double my_res = 0;
    volatile double my_num = 0.12345678899;

    asm("fldl %1\n\t"
        "fadd %%st, %%st\n\t"
        "fstl %0\n\t"
        : "=m"(my_res)
        : "m"(my_num)
        :);

    return my_res;
}

double enclave_check_abi()
{
    double retval = NAN;
    oe_result_t result = OE_UNEXPECTED;
    abi_state_t before_ocall_state = {};
    abi_state_t after_ocall_state = {};

    /* Marshalling struct cloned from abi_t.c, needs to be at least 16-bytes */
    typedef struct _host_check_abi_args_t
    {
        oe_result_t _result;
        void* deepcopy_out_buffer;
        size_t deepcopy_out_buffer_size;
        double _retval;
    } host_check_abi_args_t;

    /* Helper struct definition to manually flatten out ocall buffer with
     * standard ocall parameters and args for host_check_abi. This test
     * unrolls the EDL generated call stubs so that it can directly invoke
     * the oe_ocall directly to check its ABI handling */
    typedef struct _flat_ocall_args
    {
        oe_call_host_function_args_t host_function_args;
        host_check_abi_args_t check_abi_args;
    } flat_ocall_args_t;

    /* abi_fcn_id_host_check_abi is defined in abi_t.c, must be kept in sync */
    static const size_t abi_fcn_id_host_check_abi = 0;
    const flat_ocall_args_t args_template = {
        {.function_id = abi_fcn_id_host_check_abi,
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

    /* Alloc and initialize host_check_abi OCALL args buffer */
    flat_ocall_args_t* args =
        (flat_ocall_args_t*)oe_allocate_ocall_buffer(sizeof(args_template));
    if (!args)
        goto done;

    /* Note that the OCALL code enforces that input_buffer must be provided
     * and at least 16-bytes, even though it is not used by host_check_abi,
     * so the test assigns it the same buffer as the output_buffer */
    memcpy(args, &args_template, sizeof(args_template));
    args->host_function_args.input_buffer = &args->check_abi_args;
    args->host_function_args.output_buffer = &args->check_abi_args;

    /* Set up and cache ABI test state */
    set_test_abi_state();
    read_abi_state(&before_ocall_state);

    /* Invoke oe_ocall directly to test the ocall transition ABI handling */
    result = oe_ocall(OE_OCALL_CALL_HOST_FUNCTION, (uint64_t)args, NULL);

    /* Snap the ABI state immediately on return and clear test manipulations */
    read_abi_state(&after_ocall_state);
    reset_test_abi_state();

    /* Check that oe_ocall succeeded */
    if (result != OE_OK)
        goto done;

    /* Check the host_check_abi function succeeded and produced output */
    if (args->host_function_args.result != OE_OK)
        goto done;

    if (args->host_function_args.output_bytes_written !=
        sizeof(args_template.check_abi_args))
        goto done;

    /* Check the enclave_check_abi function returned expected value */
    if (args->check_abi_args._retval != EXPECTED_CHECK_ABI_RETURN_VALUE)
        goto done;

    /* Verify expected ABI state around oe_ocall is preserved */
    if (!is_same_abi_state(&before_ocall_state, &after_ocall_state))
        goto done;

    retval = args->check_abi_args._retval;

done:
    return retval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */
