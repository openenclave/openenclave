// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/context.h>
#include <openenclave/internal/cpuid.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "asmdefs.h"
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

    // Change the rip of oe_context to the real exception address.
    oe_context->rip = td->base.exception_address;

    // Compose the oe_exception_record_t.
    // N.B. In second pass exception handling, the XSTATE is recovered by SGX
    // hardware correctly on ERESUME, so we don't touch the XSTATE.
    oe_exception_record_t oe_exception_record = {0};
    oe_exception_record.code = td->base.exception_code;
    oe_exception_record.flags = td->base.exception_flags;
    oe_exception_record.address = td->base.exception_address;
    oe_exception_record.context = oe_context;

    // Refer to oe_enter in host/sgx/enter.c. The contract we defined for EENTER
    // is the RBP should not change after return from EENTER.
    // When the exception is handled, restores the host RBP, RSP to the
    // value when regular ECALL happens before first pass exception
    // handling.
    td->host_rbp = td->host_previous_rbp;
    td->host_rsp = td->host_previous_rsp;
    td->host_ecall_context = td->host_previous_ecall_context;

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

    // Jump to the point where oe_context refers to and continue.
    if (handler_ret == OE_EXCEPTION_CONTINUE_EXECUTION)
    {
        oe_continue_execution(oe_exception_record.context);

        // Code should never run to here.
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
    OE_UNUSED(arg_in);

    // Verify if the first SSA has valid exception info.
    if (_get_enclave_thread_first_ssa_info(td, &ssa_info) != 0)
    {
        *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    sgx_ssa_gpr_t* ssa_gpr =
        (sgx_ssa_gpr_t*)(((uint8_t*)ssa_info.base_address) + ssa_info.frame_byte_size - OE_SGX_GPR_BYTE_SIZE);
    if (!ssa_gpr->exit_info.as_fields.valid)
    {
        // Not a valid/expected enclave exception;
        *arg_out = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    // Get the exception address, code, and flags.
    td->base.exception_address = ssa_gpr->rip;
    td->base.exception_code = OE_EXCEPTION_UNKNOWN;
    for (uint32_t i = 0; i < OE_COUNTOF(g_vector_to_exception_code_mapping);
         i++)
    {
        if (g_vector_to_exception_code_mapping[i].sgx_vector ==
            ssa_gpr->exit_info.as_fields.vector)
        {
            td->base.exception_code =
                g_vector_to_exception_code_mapping[i].exception_code;
            break;
        }
    }

    td->base.exception_flags = 0;
    if (ssa_gpr->exit_info.as_fields.exit_type == SGX_EXIT_TYPE_HARDWARE)
    {
        td->base.exception_flags |= OE_EXCEPTION_FLAGS_HARDWARE;
    }
    else if (ssa_gpr->exit_info.as_fields.exit_type == SGX_EXIT_TYPE_SOFTWARE)
    {
        td->base.exception_flags |= OE_EXCEPTION_FLAGS_SOFTWARE;
    }

    if (td->base.exception_code == OE_EXCEPTION_ILLEGAL_INSTRUCTION &&
        _emulate_illegal_instruction(ssa_gpr) == 0)
    {
        // Restore the RBP & RSP as required by return from EENTER
        td->host_rbp = td->host_previous_rbp;
        td->host_rsp = td->host_previous_rsp;
        td->host_ecall_context = td->host_previous_ecall_context;

        // Advance RIP to the next instruction for continuation
        ssa_gpr->rip += 2;
    }
    else
    {
        // Modify the ssa_gpr so that e_resume will go to second pass exception
        // handler.
        ssa_gpr->rip = (uint64_t)oe_exception_dispatcher;
    }

    // Cleanup the exception flag to avoid the exception handler is called
    // again.
    ssa_gpr->exit_info.as_fields.valid = 0;

    // Acknowledge this exception is an enclave exception, host should let keep
    // running, and let enclave handle the exception.
    *arg_out = OE_EXCEPTION_CONTINUE_EXECUTION;
    return;
}

/*
**==============================================================================
**
** void oe_cleanup_xstates(void)
**
**  Cleanup all XSTATE registers that include both legacy registers and extended
**  registers.
**
**==============================================================================
*/

void oe_cleanup_xstates(void)
{
    // Temporary workaround for #144 xrstor64 fault with optimized builds as
    // reserved guard pages
    // are incorrectly accessed. Xsave area is increased from 0x240 to 0x1000.
    // Making these static
    OE_ALIGNED(XSAVE_ALIGNMENT)
    static uint8_t
        xsave_area[MINIMAL_XSTATE_AREA_LENGTH]; //#144 Making this static
//__builtin_ia32_xrstor64 has different argument types in clang and gcc
#ifdef __clang__
    uint64_t restore_mask = ~((uint64_t)0x0);
#else
    int64_t restore_mask = ~(0x0);
#endif

    // The legacy registers(F87, SSE) values will be loaded from the
    // LEGACY_XSAVE_AREA that at beginning of xsave_area.The extended registers
    // will be initialized to their default values.
    __builtin_ia32_xrstor64(xsave_area, restore_mask);

    return;
}
