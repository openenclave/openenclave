// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include "context.h"
#include "cpuid.h"
#include "init.h"
#include "td.h"

#define MAX_EXCEPTION_HANDLER_COUNT 64

// The spin lock to synchronize the exception handler access.
static oe_spinlock_t g_exception_lock = OE_SPINLOCK_INITIALIZER;

// Current registered exception handler count.
uint32_t g_current_exception_handler_count = 0;

// Current registered exception handlers.
oe_vectored_exception_handler_t
    g_exception_handler_arr[MAX_EXCEPTION_HANDLER_COUNT];

oe_result_t oe_add_vectored_exception_handler(
    bool is_first_handler,
    oe_vectored_exception_handler_t vectored_handler)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_result_t lock_ret = OE_UNEXPECTED;

    // Sanity check.
    if (vectored_handler == NULL ||
        !oe_is_within_enclave((void*)vectored_handler, 8))
    {
        result = OE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Acquire the lock.
    lock_ret = oe_spin_lock(&g_exception_lock);
    if (lock_ret != 0)
    {
        result = OE_FAILURE;
        goto cleanup;
    }

    // Check if the input handler is already registered.
    for (uint32_t i = 0; i < g_current_exception_handler_count; i++)
    {
        if (g_exception_handler_arr[i] == vectored_handler)
        {
            result = OE_FAILURE;
            goto cleanup;
        }
    }

    // Check if there is space to add a new handler.
    if (g_current_exception_handler_count >= MAX_EXCEPTION_HANDLER_COUNT)
    {
        result = OE_FAILURE;
        goto cleanup;
    }

    // Add the new handler.
    if (!is_first_handler)
    {
        // Append the new handler if it is not the first handler.
        g_exception_handler_arr[g_current_exception_handler_count] =
            vectored_handler;
    }
    else
    {
        // Move the existing handlers backward by one if any.
        for (uint32_t i = g_current_exception_handler_count; i > 0; i--)
        {
            g_exception_handler_arr[i] = g_exception_handler_arr[i - 1];
        }

        g_exception_handler_arr[0] = vectored_handler;
    }

    result = OE_OK;
    g_current_exception_handler_count++;

cleanup:
    // Release the lock if acquired.
    if (lock_ret == 0)
    {
        oe_spin_unlock(&g_exception_lock);
    }

    return result;
}

oe_result_t oe_remove_vectored_exception_handler(
    oe_vectored_exception_handler_t vectored_handler)
{
    oe_result_t result = OE_FAILURE;
    oe_result_t lock_ret = OE_UNEXPECTED;

    // Sanity check.
    if (vectored_handler == NULL ||
        !oe_is_within_enclave((void*)vectored_handler, 8))
    {
        result = OE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Acquire the lock.
    lock_ret = oe_spin_lock(&g_exception_lock);
    if (lock_ret != 0)
    {
        goto cleanup;
    }

    for (uint32_t i = 0; i < g_current_exception_handler_count; i++)
    {
        if (vectored_handler != (void*)g_exception_handler_arr[i])
        {
            continue;
        }

        // Found the target handler, move the following handlers forward by one
        // if any.
        for (uint32_t j = i; j < g_current_exception_handler_count - 1; j++)
        {
            g_exception_handler_arr[j] = g_exception_handler_arr[j + 1];
        }

        g_current_exception_handler_count--;
        result = OE_OK;
        goto cleanup;
    }

cleanup:
    // Release the lock if acquired.
    if (lock_ret == 0)
    {
        oe_spin_unlock(&g_exception_lock);
    }

    return result;
}

typedef struct _ssa_info
{
    void* base_address;
    uint64_t frame_byte_size;
} SSA_Info;

/*
**==============================================================================
**
** _get_enclave_thread_first_ssa_info()
**
**     Get the enclave thread first SSA information.
**     Return 0 if success.
**
**==============================================================================
*/
static int _get_enclave_thread_first_ssa_info(
    oe_sgx_td_t* td,
    SSA_Info* ssa_info)
{
    sgx_tcs_t* tcs = (sgx_tcs_t*)td_to_tcs(td);
    uint64_t ssa_frame_size = td->base.__ssa_frame_size;
    if (ssa_frame_size == 0)
    {
        ssa_frame_size = OE_DEFAULT_SSA_FRAME_SIZE;
    }

    // Get first SSA base address and size.
    ssa_info->base_address =
        (void*)((uint8_t*)tcs + OE_SSA_FROM_TCS_BYTE_OFFSET);
    ssa_info->frame_byte_size = ssa_frame_size * OE_PAGE_SIZE;
    return 0;
}

// SGX hardware exit type, must align with Intel SDM.
#define SGX_EXIT_TYPE_HARDWARE 0x3
#define SGX_EXIT_TYPE_SOFTWARE 0x6

// Mapping between the SGX exception vector value and the OE exception code.
static struct
{
    uint32_t sgx_vector;
    uint32_t exception_code;
} g_vector_to_exception_code_mapping[] = {
    {0, OE_EXCEPTION_DIVIDE_BY_ZERO},
    {3, OE_EXCEPTION_BREAKPOINT},
    {5, OE_EXCEPTION_BOUND_OUT_OF_RANGE},
    {6, OE_EXCEPTION_ILLEGAL_INSTRUCTION},
    {13, OE_EXCEPTION_ACCESS_VIOLATION},
    {14, OE_EXCEPTION_PAGE_FAULT},
    {16, OE_EXCEPTION_X87_FLOAT_POINT},
    {17, OE_EXCEPTION_MISALIGNMENT},
    {19, OE_EXCEPTION_SIMD_FLOAT_POINT},
};

/*
**==============================================================================
**
** _emulate_illegal_instruction()
**
** Handle illegal instruction exceptions such as CPUID as part of the first
** chance exception dispatcher.
**
**==============================================================================
*/
int _emulate_illegal_instruction(sgx_ssa_gpr_t* ssa_gpr)
{
    // Emulate CPUID
    if (*((uint16_t*)ssa_gpr->rip) == OE_CPUID_OPCODE)
    {
        return oe_emulate_cpuid(
            &ssa_gpr->rax, &ssa_gpr->rbx, &ssa_gpr->rcx, &ssa_gpr->rdx);
    }

    return -1;
}

/*
**==============================================================================
**
** oe_real_exception_dispatcher(oe_context_t *oe_context)
**
**  The real (second pass) exception dispatcher. It is called by
**  oe_exception_dispatcher. This function composes the valid
**  oe_exception_record_t and calls the registered exception handlers one by
**  one.  If a handler returns OE_EXCEPTION_CONTINUE_EXECUTION, this function
**  will continue execution on the context. Otherwise the enclave will be
**  aborted due to an unhandled exception.
**
**==============================================================================
*/
void oe_real_exception_dispatcher(oe_context_t* oe_context)
{
    oe_sgx_td_t* td = oe_sgx_get_td();

    /* Validate the td state, which ensures the function
     * is only invoked after oe_virtual_exception_dispatcher */
    if (td->state != OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING)
    {
        oe_abort();
        return;
    }

    // Change the rip of oe_context to the real exception address.
    oe_context->rip = td->exception_address;

    // Compose the oe_exception_record_t.
    // N.B. In second pass exception handling, the XSTATE is recovered by SGX
    // hardware correctly on ERESUME, so we don't touch the XSTATE.
    oe_exception_record_t oe_exception_record = {0};
    oe_exception_record.code = td->exception_code;
    oe_exception_record.flags = td->exception_flags;
    oe_exception_record.address = td->exception_address;
    oe_exception_record.faulting_address = td->faulting_address;
    oe_exception_record.error_code = td->error_code;
    oe_exception_record.context = oe_context;
    /* Only pass the host signal for non-nested exceptions */
    if (td->exception_nesting_level == 1)
        oe_exception_record.host_signal_number = (uint16_t)td->host_signal;
    else
        oe_exception_record.host_signal_number = 0;

    // Refer to oe_enter in host/sgx/enter.c.
    // Restore host_ecall_context from the first EENTER (cssa=0) that allows for
    // correctly stitching the stack on EEXIT when the enclave is in the debug
    // mode
    td->host_ecall_context = td->host_previous_ecall_context;

    /* If the exception handler stack is prpoerly set, restore rsp and rbp from
     * td. Note that the case of _emulate_illegal_instruction always bypasses
     * this logic (last_ssa_rsp and last_ssa_rbp will not be set) */
    if (td->exception_handler_stack_size &&
        oe_is_within_enclave(
            (void*)td->exception_handler_stack,
            td->exception_handler_stack_size) &&
        oe_is_within_enclave(
            (void*)td->last_ssa_rsp,
            sizeof(uint64_t) && oe_is_within_enclave(
                                    (void*)td->last_ssa_rbp, sizeof(uint64_t))))
    {
        oe_exception_record.context->rsp = td->last_ssa_rsp;
        oe_exception_record.context->rbp = td->last_ssa_rbp;
    }

    // Traverse the existing exception handlers, stop when
    // OE_EXCEPTION_CONTINUE_EXECUTION is found.
    uint64_t handler_ret = OE_EXCEPTION_CONTINUE_SEARCH;
    for (uint32_t i = 0; i < g_current_exception_handler_count; i++)
    {
        handler_ret = g_exception_handler_arr[i](&oe_exception_record);
        if (handler_ret == OE_EXCEPTION_CONTINUE_EXECUTION)
        {
            break;
        }
    }

    // Clear information after all the handlers are done
    td->exception_code = 0;
    td->exception_flags = 0;
    td->exception_address = 0;
    td->faulting_address = 0;
    td->error_code = 0;
    td->last_ssa_rsp = 0;
    td->last_ssa_rbp = 0;

    /* Validate and decrease the nesting level (increased by enter.S)
     * after all the handlers finish */
    if (td->exception_nesting_level == 0)
    {
        oe_abort();
        return;
    }
    td->exception_nesting_level--;

    if (td->exception_nesting_level == 0)
    {
        /* Clear the flag if it is set after non-nested exception handling
         * is done */
        if (td->is_handling_host_signal == 1)
        {
            td->is_handling_host_signal = 0;
        }

        td->host_signal = 0;

        /* Retore the state */
        td->state = OE_TD_STATE_RUNNING;
    }
    td->previous_state = OE_TD_STATE_NULL;

    // Jump to the point where oe_context refers to and continue.
    if (handler_ret == OE_EXCEPTION_CONTINUE_EXECUTION)
    {
        oe_continue_execution(oe_exception_record.context);

        // Code should never run to here.
        oe_abort();
        return;
    }
    else if (handler_ret == OE_EXCEPTION_ABORT_EXECUTION)
    {
        oe_abort();
        return;
    }

    // Exception can't be handled by trusted handlers, abort the enclave.
    // Let the oe_abort to run on the stack where the exception happens.
    oe_exception_record.context->rip = (uint64_t)oe_abort;
    oe_continue_execution(oe_exception_record.context);

    return;
}

/*
**==============================================================================
**
** oe_virtual_exception_dispatcher(oe_sgx_td_t* td, uint64_t arg_in, uint64_t*
*arg_out)
**
**  The virtual (first pass) exception dispatcher. It checks whether or not
**  there is an exception in current enclave thread, and save minimal exception
**  context to TLS, and then return to host.
**
**==============================================================================
*/
void oe_virtual_exception_dispatcher(
    oe_sgx_td_t* td,
    uint64_t arg_in,
    uint64_t* arg_out)
{
    SSA_Info ssa_info = {0};

    /* Validate the td state, which ensures the function
     * is only invoked by the exception entry code path (see enter.S) */
    if (td->state != OE_TD_STATE_FIRST_LEVEL_EXCEPTION_HANDLING)
    {
        td->state = OE_TD_STATE_ABORTED;
        *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    // Verify if the first SSA has valid exception info.
    if (_get_enclave_thread_first_ssa_info(td, &ssa_info) != 0)
    {
        *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    /* Only keep the host signal for non-nested exceptions */
    if (td->exception_nesting_level == 1)
        td->host_signal = arg_in;

    uint64_t gprsgx_offset = (uint64_t)ssa_info.base_address +
                             ssa_info.frame_byte_size - OE_SGX_GPR_BYTE_SIZE;
    sgx_ssa_gpr_t* ssa_gpr = (sgx_ssa_gpr_t*)gprsgx_offset;

    td->exception_address = ssa_gpr->rip;
    td->exception_code = OE_EXCEPTION_UNKNOWN;

    /* Get the exception code and flags only if the exception type
     * is recognized by the SGX hardware */
    if (ssa_gpr->exit_info.as_fields.valid)
    {
        for (uint32_t i = 0; i < OE_COUNTOF(g_vector_to_exception_code_mapping);
             i++)
        {
            if (g_vector_to_exception_code_mapping[i].sgx_vector ==
                ssa_gpr->exit_info.as_fields.vector)
            {
                td->exception_code =
                    g_vector_to_exception_code_mapping[i].exception_code;
                break;
            }
        }

        td->exception_flags = 0;
        if (ssa_gpr->exit_info.as_fields.exit_type == SGX_EXIT_TYPE_HARDWARE)
        {
            td->exception_flags |= OE_EXCEPTION_FLAGS_HARDWARE;
        }
        else if (
            ssa_gpr->exit_info.as_fields.exit_type == SGX_EXIT_TYPE_SOFTWARE)
        {
            td->exception_flags |= OE_EXCEPTION_FLAGS_SOFTWARE;
        }
    }
    else
    {
        /* The unknown exception type indicates a host signal request. Validate
         * the states on the td to ensure that the thread is handling the
         * host signal */
        if (!oe_sgx_td_host_signal_registered(td, (int)td->host_signal) ||
            td->exception_nesting_level != 1 ||
            td->is_handling_host_signal != 1)
        {
            *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
            return;
        }
    }

    if (td->exception_code == OE_EXCEPTION_ILLEGAL_INSTRUCTION &&
        _emulate_illegal_instruction(ssa_gpr) == 0)
    {
        /* Refer to oe_enter in host/sgx/enter.c.
         * Restore host_ecall_context from the first EENTER (cssa=0) that allows
         * for correctly stitching the stack on EEXIT when the enclave is in the
         * debug mode */
        td->host_ecall_context = td->host_previous_ecall_context;

        /* Restore the state using the previous_state and update
         * the previous_state. The latter allows the exiting flow
         * to skip updating the state. */
        td->state = td->previous_state;
        td->previous_state = OE_TD_STATE_FIRST_LEVEL_EXCEPTION_HANDLING;

        /* Validate and decrease the nesting level (increased by enter.S)
         * after all the handlers finish */
        if (td->exception_nesting_level == 0)
        {
            td->state = OE_TD_STATE_ABORTED;
            *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
            return;
        }
        td->exception_nesting_level--;

        // Advance RIP to the next instruction for continuation
        ssa_gpr->rip += 2;
    }
    else
    {
        /* The following codes can only be captured with SGX2 and the
         * MISCSELECT[0] bit is set to 1. */
        if (td->exception_code == OE_EXCEPTION_PAGE_FAULT ||
            td->exception_code == OE_EXCEPTION_ACCESS_VIOLATION)
        {
            sgx_exinfo_t* exinfo =
                (sgx_exinfo_t*)(gprsgx_offset - OE_SGX_MISC_BYTE_SIZE);
            td->faulting_address = exinfo->maddr;
            td->error_code = exinfo->errcd;
        }

        /* Update the state here to indicate the second-level exception
         * handler is running next. This allows both exiting and the following
         * entering flows to skip updating the state; i.e., the second-level
         * exception handler can run with this state. */
        td->state = OE_TD_STATE_SECOND_LEVEL_EXCEPTION_HANDLING;

        // Modify the ssa_gpr so that e_resume will go to second pass exception
        // handler.
        ssa_gpr->rip = (uint64_t)oe_exception_dispatcher;

        /* If the exception handler stack is properly set, update the rsp in the
         * SSA to the bottom of the stack. Also, save the rsp and rbp in the SSA
         * before the assignment, which are used to resume the execution after
         * exception handling. */
        if (td->exception_handler_stack_size &&
            oe_is_within_enclave(
                (void*)td->exception_handler_stack,
                td->exception_handler_stack_size))
        {
            td->last_ssa_rsp = ssa_gpr->rsp;
            td->last_ssa_rbp = ssa_gpr->rbp;
            ssa_gpr->rsp =
                td->exception_handler_stack + td->exception_handler_stack_size;
        }
    }

    // Cleanup the exception flag to avoid the exception handler is called
    // again.
    ssa_gpr->exit_info.as_fields.valid = 0;

    // Acknowledge this exception is an enclave exception, host should let keep
    // running, and let enclave handle the exception.
    *arg_out = OE_EXCEPTION_CONTINUE_EXECUTION;
    return;
}
