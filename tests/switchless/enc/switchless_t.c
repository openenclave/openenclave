// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "switchless_t.h"
#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/trace.h>

#include <openenclave/internal/print.h>

OE_EXTERNC_BEGIN

#if (__SWITCHLESS__)
/* todo:
   These forward declarations, _oe_synchronous_switchless_ecalls_table and
     _oe_synchronous_switchless_ecalls_table_size, are provided for
     handle_synchronous_switchless_ecall and should be moved when that function
     is moved.
 */
/**** forward declarations for synchronous switchless ECALL function table ****/
oe_ecall_func_t __oe_synchronous_switchless_ecalls_table[];
size_t __oe_synchronous_switchless_ecalls_table_size;

/* todo:
   This function belongs somewhere else.
   This function provides functionality similar to
     _handle_call_enclave_function from enclave/core/sgx/calls.c.
   It handles the marshaling of data and invoking the corresponding function
     defined in the enclave.
   The forward declarations, _oe_synchronous_switchless_ecalls_table and
     _oe_synchronous_switchless_ecalls_table_size, are provided for this
     function and should be moved when this function is moved.
 */
/****** infrastructure ECALL function wrappers  *************/
oe_result_t handle_synchronous_switchless_ecall(sc_queue_node* p_queue_node)
{
    // oe_host_printf("    <handle_synchronous_switchless_ecall>\n");
    oe_result_t result = OE_OK;

    // find the function
    if (__oe_synchronous_switchless_ecalls_table_size >
        p_queue_node->function_id)
    {
        // I really don't see a purpose for duplicating the buffers.
        // I see that this is done in _handle_call_enclave_function in
        //   enclave/core/sgx/calls.c but I do not see what problem it solves.

        oe_ecall_func_t func =
            __oe_synchronous_switchless_ecalls_table[p_queue_node->function_id];

        // Allocate buffers in enclave memory
        // create buffers in the enclave memory and copy the data
        // look at _handle_call_enclave_function in
        //   enclave/core/sgx/calls.c[202]

        // Ensure that the input and output buffers are valid.
        if (p_queue_node->input_buffer != NULL &&
            p_queue_node->input_buffer_size > 0 &&
            oe_is_outside_enclave(
                p_queue_node->input_buffer, p_queue_node->input_buffer_size) &&
            (p_queue_node->input_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) ==
                0 &&
            p_queue_node->output_buffer != NULL &&
            p_queue_node->output_buffer_size > 0 &&
            oe_is_outside_enclave(
                p_queue_node->output_buffer,
                p_queue_node->output_buffer_size) &&
            (p_queue_node->output_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) ==
                0)
        {
            size_t buffer_size = 0;

            if (OE_OK == (result = oe_safe_add_u64(
                              p_queue_node->input_buffer_size,
                              p_queue_node->output_buffer_size,
                              &buffer_size)))
            {
                uint8_t* buffer = NULL;

                // Allocate buffers in enclave memory
                if (NULL != (buffer = oe_malloc(buffer_size)))
                {
                    size_t output_bytes_written = 0;

                    // Copy input buffer to the enclave buffer
                    memcpy(
                        buffer,
                        p_queue_node->input_buffer,
                        p_queue_node->input_buffer_size);

                    // Clear the output buffer.
                    // This ensures reproducible behavior if say the function is
                    // reading from the output buffer.
                    memset(
                        buffer + p_queue_node->input_buffer_size,
                        0,
                        p_queue_node->output_buffer_size);

                    // Call the function.
                    func(
                        buffer,
                        p_queue_node->input_buffer_size,
                        buffer + p_queue_node->input_buffer_size,
                        p_queue_node->output_buffer_size,
                        &output_bytes_written);

                    // Copy the output buffer to host memory.
                    // (should there be bounds checking here?)
                    memcpy(
                        p_queue_node->output_buffer,
                        buffer + p_queue_node->input_buffer_size,
                        output_bytes_written);

                    // The ECALL succeeded.
                    p_queue_node->output_bytes_written = output_bytes_written;

                    oe_free(buffer);
                }
                else
                {
                    result = OE_OUT_OF_MEMORY;
                }
            }
        }
        else
        {
            // invalid input and/or output buffer(s)
            result = OE_INVALID_PARAMETER;
        }
    }
    else
    {
        result = OE_NOT_FOUND;
    }

    // Trace any error.
    if (OE_OK != result)
    {
        OE_TRACE_ERROR(":%s", oe_result_str(result));
    }

    // Set the result.
    p_queue_node->result = result;
    // if (OE_OK != result)
    // {
    //     oe_host_printf("      FAILED(2): %s\n", oe_result_str(result));
    // }

    // Signal the host.
    // oe_host_printf("    </handle_synchronous_switchless_ecall>\n");
    __atomic_clear(&(p_queue_node->data.sync.lock), __ATOMIC_RELEASE);

    return result;
}
#endif // __SWITCHLESS__

#if (__SWITCHLESS__)
/* todo:
  This is the worker thread.
  Currently this is implemented as a standard ecall.
  This should be moved out of the generated file and into a library.
  Perhaps the worker thread should be moved into enclave/core/sgx/calls.c
 */
void ecall_switchless_enc_worker_thread(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t _result = OE_OK;

    /* Prepare parameter */
    switchless_enc_worker_thread_args_t* pargs_in =
        (switchless_enc_worker_thread_args_t*)input_buffer;
    switchless_enc_worker_thread_args_t* pargs_out =
        (switchless_enc_worker_thread_args_t*)output_buffer;

    size_t input_buffer_offset = 0;
    size_t output_buffer_offset = 0;
    OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));
    OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));

    /* Make sure input and output buffers lie within the enclave */
    if (!input_buffer || !oe_is_within_enclave(input_buffer, input_buffer_size))
    {
        goto done;
    }

    if (!output_buffer ||
        !oe_is_within_enclave(output_buffer, output_buffer_size))
    {
        goto done;
    }

    /* lfence after checks */
    oe_lfence();

    /* this is the worker thread loop */
    size_t count = 0;
    while (SC_RUNNING == sc_get_state(pargs_in->psc) &&
           pargs_in->psc->count_limit > count++)
    {
        sc_queue_node* p_queue_node = sc_pop_enc_queue(pargs_in->psc);
        if (p_queue_node)
        {
            count = 0;
            switch (p_queue_node->type)
            {
                case ET_SYNCHRONOUS:
                    handle_synchronous_switchless_ecall(p_queue_node);
                    break;
                case ET_ASYNCHRONOUS:
                    // todo
                    break;
                case ET_CALLBACK:
                    // todo
                    break;
                default:
                    break;
            }
        }
    }
    sc_set_state(pargs_in->psc, SC_STOPPED);

    /* Success. */
    _result = OE_OK;
    *output_bytes_written = output_buffer_offset;

done:
    if (pargs_out && output_buffer_size >= sizeof(*pargs_out))
    {
        pargs_out->_result = _result;
    }
}
#endif // __SWITCHLESS__

/****** standard ECALL function wrappers  *************/
void ecall_standard_enc_sum(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    // oe_host_printf("    <ecall_standard_enc_sum>\n");
    oe_result_t _result = OE_FAILURE;

    /* Prepare parameters */
    standard_enc_sum_args_t* pargs_in = (standard_enc_sum_args_t*)input_buffer;
    standard_enc_sum_args_t* pargs_out =
        (standard_enc_sum_args_t*)output_buffer;

    size_t input_buffer_offset = 0;
    size_t output_buffer_offset = 0;
    OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));
    OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));

    /* Make sure input and output buffers lie within the enclave */
    if (!input_buffer || !oe_is_within_enclave(input_buffer, input_buffer_size))
    {
        goto done;
    }

    if (!output_buffer ||
        !oe_is_within_enclave(output_buffer, output_buffer_size))
    {
        goto done;
    }

    /* Set in and in-out pointers */

    /* Set out and in-out pointers. In-out parameters are copied to output
       buffer. */

    /* lfence after checks */
    oe_lfence();

    /* Call user function */
    pargs_out->_retval = standard_enc_sum(pargs_in->arg1, pargs_in->arg2);

    /* Success. */
    _result = OE_OK;
    *output_bytes_written = output_buffer_offset;

done:
    if (pargs_out && output_buffer_size >= sizeof(*pargs_out))
    {
        pargs_out->_result = _result;
    }
    // if (OE_OK != _result)
    // {
    //     oe_host_printf("      FAILED: %s\n", oe_result_str(_result));
    // }
    // oe_host_printf("    </ecall_standard_enc_sum>\n");
}

/****** synchronized switchless ECALL function wrappers  *************/
void ecall_synchronous_switchless_enc_sum(
    uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t _result = OE_FAILURE;

    /* Prepare parameters */
    standard_enc_sum_args_t* pargs_in = (standard_enc_sum_args_t*)input_buffer;
    standard_enc_sum_args_t* pargs_out =
        (standard_enc_sum_args_t*)output_buffer;

    size_t input_buffer_offset = 0;
    size_t output_buffer_offset = 0;
    OE_ADD_SIZE(input_buffer_offset, sizeof(*pargs_in));
    OE_ADD_SIZE(output_buffer_offset, sizeof(*pargs_out));

    /* Make sure input and output buffers lie within the enclave */
    if (!input_buffer || !oe_is_within_enclave(input_buffer, input_buffer_size))
    {
        goto done;
    }

    if (!output_buffer ||
        !oe_is_within_enclave(output_buffer, output_buffer_size))
    {
        goto done;
    }

    /* Set in and in-out pointers */

    /* Set out and in-out pointers. In-out parameters are copied to output
       buffer. */

    /* lfence after checks */
    oe_lfence();

    /* Call user function */
    pargs_out->_retval =
        synchronous_switchless_enc_sum(pargs_in->arg1, pargs_in->arg2);

    /* Success. */
    _result = OE_OK;
    *output_bytes_written = output_buffer_offset;

done:
    if (pargs_out && output_buffer_size >= sizeof(*pargs_out))
    {
        pargs_out->_result = _result;
    }
}

/****** standard ECALL function table  *************/
oe_ecall_func_t __oe_ecalls_table[] = {
#if (__SWITCHLESS__)
    (oe_ecall_func_t)ecall_switchless_enc_worker_thread,
    (oe_ecall_func_t)ecall_standard_enc_sum,
#else  // __SWITCHLESS__
    (oe_ecall_func_t)ecall_standard_enc_sum,
    (oe_ecall_func_t)ecall_synchronous_switchless_enc_sum,
#endif // __SWITCHLESS__
};

size_t __oe_ecalls_table_size = OE_COUNTOF(__oe_ecalls_table);

#if (__SWITCHLESS__)
/****** synchronous switchless ECALL function table  *************/
oe_ecall_func_t __oe_synchronous_switchless_ecalls_table[] = {
    (oe_ecall_func_t)ecall_synchronous_switchless_enc_sum,
};

size_t __oe_synchronous_switchless_ecalls_table_size =
    OE_COUNTOF(__oe_synchronous_switchless_ecalls_table);
#endif // __SWITCHLESS__

OE_EXTERNC_END
