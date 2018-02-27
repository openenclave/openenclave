#include <openenclave/bits/atexit.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/enclave.h>
#include "asmdefs.h"
#include "init.h"
#include "td.h"

#define MAX_EXCEPTION_HANDLER_COUNT 64

// The spin lock to synchronize the exception handler access.
static OE_Spinlock g_exception_lock = OE_SPINLOCK_INITIALIZER;

// Current registered exception handler count.
uint32_t g_current_exception_handler_count = 0;

// Current registered exception handlers.
POE_VECTORED_EXCEPTION_HANDLER
g_exception_handler_arr[MAX_EXCEPTION_HANDLER_COUNT];

void* OE_AddVectoredExceptionHandler(
    uint64_t isFirstHandler,
    POE_VECTORED_EXCEPTION_HANDLER vectoredHandler)
{
    void* func_ret = NULL;
    int lock_ret = -1;

    // Sanity check.
    if (vectoredHandler == NULL ||
        !OE_IsWithinEnclave((void*)vectoredHandler, 8))
    {
        goto cleanup;
    }

    // Acquire the lock.
    lock_ret = OE_SpinLock(&g_exception_lock);
    if (lock_ret != 0)
    {
        goto cleanup;
    }

    // Check if the input handler is already registered.
    for (uint32_t i = 0; i < g_current_exception_handler_count; i++)
    {
        if (g_exception_handler_arr[i] == vectoredHandler)
        {
            goto cleanup;
        }
    }

    // Check if there is space to add a new handler.
    if (g_current_exception_handler_count >= MAX_EXCEPTION_HANDLER_COUNT)
    {
        goto cleanup;
    }

    // Add the new handler.
    if (isFirstHandler == 0)
    {
        // Append the new handler if it is not the first handler.
        g_exception_handler_arr[g_current_exception_handler_count] =
            vectoredHandler;
    }
    else
    {
        // Move the existing handlers backward by one if any.
        for (uint32_t i = g_current_exception_handler_count; i > 0; i--)
        {
            g_exception_handler_arr[i] = g_exception_handler_arr[i - 1];
        }

        g_exception_handler_arr[0] = vectoredHandler;
    }

    func_ret = vectoredHandler;
    g_current_exception_handler_count++;

cleanup:
    // Release the lock if acquired.
    if (lock_ret == 0)
    {
        OE_SpinUnlock(&g_exception_lock);
    }

    return func_ret;
}

uint64_t OE_RemoveVectoredExceptionHandler(void* vectoredHandler)
{
    uint64_t func_ret = 1;
    int lock_ret = -1;

    // Sanity check.
    if (vectoredHandler == NULL ||
        !OE_IsWithinEnclave((void*)vectoredHandler, 8))
    {
        goto cleanup;
    }

    // Acquire the lock.
    lock_ret = OE_SpinLock(&g_exception_lock);
    if (lock_ret != 0)
    {
        goto cleanup;
    }

    for (uint32_t i = 0; i < g_current_exception_handler_count; i++)
    {
        if (vectoredHandler != (void*)g_exception_handler_arr[i])
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
        func_ret = 0;
        goto cleanup;
    }

cleanup:
    // Release the lock if acquired.
    if (lock_ret == 0)
    {
        OE_SpinUnlock(&g_exception_lock);
    }

    return func_ret;
}

typedef struct _SSA_Info
{
    void* base_address;
    uint64_t frame_byte_size;
} SSA_Info;

/*
**==============================================================================
**
** _GetEnclaveThreadFirstSsaInfo()
**
**     Get the enclave thread first SSA information.
**     Return 0 if success.
**
**==============================================================================
*/
static int _GetEnclaveThreadFirstSsaInfo(TD* td, SSA_Info* ssa_info)
{
    SGX_TCS* tcs = (SGX_TCS*)TD_ToTCS(td);
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
#define SGX_EXIT_TYPE_HADEWARE 0x3
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
** _OE_ExceptionDispatcher(OE_CONTEXT *oe_context)
**
**  The real (second pass) exception dispatcher. It is called by
**  OE_ExceptionDispatcher. This function composes the valid OE_EXCEPTION_RECORD
**  and calls the registered exception handlers one by one. If a handler returns
**  OE_EXCEPTION_CONTINUE_EXECUTION, this function will continue execution on
**  the context. Otherwise the enclave will be aborted due to an unhandled
**  exception.
**
**==============================================================================
*/
void _OE_ExceptionDispatcher(OE_CONTEXT* oe_context)
{
    TD* td = TD_Get();

    // Change the rip of oe_context to the real exception address.
    oe_context->rip = td->base.exception_address;

    // Compose the OE_EXCEPTION_RECORD.
    // N.B. In second pass exception handling, the XSTATE is recovered by SGX
    // hardware correctly on ERESUME, so we don't touch the XSTATE.
    OE_EXCEPTION_RECORD oe_exception_record;
    OE_Memset(&oe_exception_record, 0, sizeof(OE_EXCEPTION_RECORD));
    oe_exception_record.code = td->base.exception_code;
    oe_exception_record.flags = td->base.exception_flags;
    oe_exception_record.address = td->base.exception_address;
    oe_exception_record.context = oe_context;

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
        OE_ContinueExecution(oe_exception_record.context);

        // Code should never run to here.
        OE_Abort();
        return;
    }

    // Exception can't be handled by trusted handlers, smash the enclave.
    OE_Abort();
    return;
}

/*
**==============================================================================
**
** _OE_VirtualExceptionDispatcher(TD* td, uint64_t argIn, uint64_t* argOut)
**
**  The virtual (first pass) exception dispatcher. It checks whether or not
**  there is an exception in current enclave thread, and save minimal exception
**  context to TLS, and then return to host.
**
**==============================================================================
*/
void _OE_VirtualExceptionDispatcher(TD* td, uint64_t argIn, uint64_t* argOut)
{
    SSA_Info ssa_info;
    OE_Memset(&ssa_info, 0, sizeof(SSA_Info));

    // Verify if the first SSA has valid exception info.
    if (_GetEnclaveThreadFirstSsaInfo(td, &ssa_info) != 0)
    {
        *argOut = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    SGX_SsaGpr* ssa_gpr =
        (SGX_SsaGpr*)(((uint8_t*)ssa_info.base_address) + ssa_info.frame_byte_size - OE_SGX_GPR_BYTE_SIZE);
    if (!ssa_gpr->exitInfo.asFields.valid)
    {
        // Not a valid/expected enclave exception;
        *argOut = OE_EXCEPTION_CONTINUE_SEARCH;
        return;
    }

    // Get the exception address, code, and flags.
    td->base.exception_address = ssa_gpr->rip;
    td->base.exception_code = OE_EXCEPTION_UNKOWN;
    for (uint32_t i = 0; i < OE_COUNTOF(g_vector_to_exception_code_mapping);
         i++)
    {
        if (g_vector_to_exception_code_mapping[i].sgx_vector ==
            ssa_gpr->exitInfo.asFields.vector)
        {
            td->base.exception_code =
                g_vector_to_exception_code_mapping[i].exception_code;
            break;
        }
    }

    td->base.exception_flags = 0;
    if (ssa_gpr->exitInfo.asFields.exitType == SGX_EXIT_TYPE_HADEWARE)
    {
        td->base.exception_flags |= OE_EXCEPTION_HARDWARE;
    }
    else if (ssa_gpr->exitInfo.asFields.exitType == SGX_EXIT_TYPE_SOFTWARE)
    {
        td->base.exception_flags |= OE_EXCEPTION_SOFTWARE;
    }

    // Modify the ssa_gpr so that e_resume will go to second pass exception
    // handler.
    ssa_gpr->rip = (uint64_t)OE_ExceptionDispatcher;

    // Cleanup the exception flag to avoid the exception handler is called
    // again.
    ssa_gpr->exitInfo.asFields.valid = 0;

    // Acknowledge this exception is an enclave exception, host should let keep
    // running, and let enclave handle the exception.
    *argOut = OE_EXCEPTION_CONTINUE_EXECUTION;
    return;
}
