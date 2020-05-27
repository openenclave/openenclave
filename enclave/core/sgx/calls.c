// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../calls.h"
#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/ecall_context.h>
#include <openenclave/internal/sgx/td.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>
#include "../../../common/sgx/sgxmeasure.h"
#include "../../sgx/report.h"
#include "../arena.h"
#include "../atexit.h"
#include "../tracee.h"
#include "asmdefs.h"
#include "core_t.h"
#include "cpuid.h"
#include "handle_ecall.h"
#include "init.h"
#include "platform_t.h"
#include "report.h"
#include "switchlesscalls.h"
#include "td.h"

oe_result_t __oe_enclave_status = OE_OK;
uint8_t __oe_initialized = 0;

extern bool oe_disable_debug_malloc_check;

/*
**==============================================================================
**
** Glossary:
**
**     TCS      - Thread control structure. The TCS is an address passed to
**                EENTER and passed onto the entry point (_start). The TCS
**                is the address of a TCS page in the enclave memory. This page
**                is not accessible to the enclave itself. The enclave stores
**                state about the execution of a thread in this structure,
**                such as the entry point (TCS.oentry), which refers to the
**                _start function. It also maintains the index of the
**                current SSA (TCS.cssa) and the number of SSA's (TCS.nssa).
**
**     oe_sgx_td_t       - Thread data. Per thread data as defined by the
**                oe_thread_data_t structure and extended by the oe_sgx_td_t
*structure.
**                This structure records the stack pointer of the last EENTER.
**
**     SP       - Stack pointer. Refers to the enclave's stack pointer.
**
**     BP       - Base pointer. Refers to the enclave's base pointer.
**
**     HOSTSP   - Host stack pointer. Refers to the host's stack pointer as
**                received in the EENTER call.
**
**     HOSTBP   - Host base pointer. Refers to the host's base pointer as
**                received in the EENTER call.
**
**     AEP      - Asynchronous Exception Procedure. This procedure is passed
**                by the host to EENTER. If a fault occurs while in the enclave,
**                the hardware calls this procedure. The procedure may
**                terminate or call ERESUME to continue executing in the
**                enclave.
**
**     AEX      - Asynchronous Exception (occurs when enclave faults). The
**                hardware transfers control to a host AEP (passed as a
**                parameter to EENTER).
**
**     SSA      - State Save Area. When a fault occurs in the enclave, the
**                hardware saves the state here (general purpose registers)
**                and then transfers control to the host AEP. If the AEP
**                executes the ERESUME instruction, the hardware restores the
**                state from the SSA.
**
**     EENTER   - An untrusted instruction that is executed by the host to
**                enter the enclave. The caller passes the address of a TCS page
**                within the enclave, an AEP, and any parameters in the RDI and
**                RSI registers. This implementation passes the operation
**                number (FUNC) in RDI and a pointer to the arguments structure
**                (ARGS) in RSI.
**
**     EEXIT    - An instruction that is executed by the host to exit the
**                enclave and return control to the host. The caller passes
**                the address of some instruction to jump to (RETADDR) in the
**                RBX register and an AEP in the RCX register (null at this
**                time).
**
**     RETADDR  - Refers to the address of the return instruction that the
**                hardware jumps to from EEXIT. This is an instruction in
**                host immediately following the instruction that executed
**                EENTER.
**
**     CSSA     - The current SSA slot index (as given by TCS.cssa). EENTER
**                passes a CSSA parameter (RAX) to _start(). A CSSA of zero
**                indicates a normal entry. A non-zero CSSA indicates an
**                exception entry (an AEX has occurred).
**
**     NSSA     - The number of SSA slots in the thread section (of this
**                enclave. If CSSA == NSSA, then the SSA's have been exhausted
**                and the EENTER instruction will fault.
**
**     ECALL    - A function call initiated by the host and carried out by
**                the enclave. The host executes the EENTER instruction to
**                enter the enclave.
**
**     ERET     - A return from an ECALL initiated by the enclave. The
**                enclave executes the EEXIT instruction to exit the enclave.
**
**     OCALL    - A function call initiated by the enclave and carried out
**                by the host. The enclave executes the EEXIT instruction to
**                exit the enclave.
**
**     ORET     - A return from an OCALL initiated by the host. The host
**                executes the EENTER instruction to enter the enclave.
**
**==============================================================================
*/

#ifdef OE_WITH_EXPERIMENTAL_EEID
extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;
extern oe_eeid_t* oe_eeid;
extern size_t oe_eeid_extended_size;

int _is_eeid_base_image(const volatile oe_sgx_enclave_properties_t* properties)
{
    return properties->header.size_settings.num_heap_pages == 0 &&
           properties->header.size_settings.num_stack_pages == 0 &&
           properties->header.size_settings.num_tcs == 1;
}

static oe_result_t _eeid_patch_memory_sizes()
{
    oe_result_t r = OE_OK;

    if (_is_eeid_base_image(&oe_enclave_properties_sgx))
    {
        uint8_t* enclave_base = (uint8_t*)__oe_get_enclave_base();
        uint8_t* heap_base = (uint8_t*)__oe_get_heap_base();
        oe_eeid_marker_t* marker = (oe_eeid_marker_t*)heap_base;
        oe_eeid = (oe_eeid_t*)(enclave_base + marker->offset);
        oe_eeid_extended_size = marker->size;

        // Wipe the marker page
        memset(heap_base, 0, OE_PAGE_SIZE);
    }

    return r;
}
#endif

/*
**==============================================================================
**
** _handle_init_enclave()
**
**     Handle the OE_ECALL_INIT_ENCLAVE from host and ensures that each state
**     initialization function in the enclave only runs once.
**
**==============================================================================
*/
static oe_result_t _handle_init_enclave(uint64_t arg_in)
{
    static bool _once = false;
    oe_result_t result = OE_OK;
    /* Double checked locking (DCLP). */
    bool o = _once;

    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (o == false)
    {
        static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
        oe_spin_lock(&_lock);

        if (_once == false)
        {
            oe_enclave_t* enclave = (oe_enclave_t*)arg_in;

#ifdef OE_WITH_EXPERIMENTAL_EEID
            OE_CHECK(_eeid_patch_memory_sizes());
#endif

#ifdef OE_USE_BUILTIN_EDL
            /* Install the common TEE ECALL function table. */
            OE_CHECK(oe_register_core_ecall_function_table());

            /* Install the SGX ECALL function table. */
            OE_CHECK(oe_register_platform_ecall_function_table());
#endif // OE_USE_BUILTIN_EDL

            if (!oe_is_outside_enclave(enclave, 1))
                OE_RAISE(OE_INVALID_PARAMETER);

            oe_enclave = enclave;

            /* Initialize the CPUID table before calling global constructors. */
            OE_CHECK(oe_initialize_cpuid());

            /* Initialize the allocator */
            oe_allocator_init(
                (void*)__oe_get_heap_base(), (void*)__oe_get_heap_end());

            /* Call global constructors. Now they can safely use simulated
             * instructions like CPUID. */
            oe_call_init_functions();

            /* DCLP Release barrier. */
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            _once = true;
            __oe_initialized = 1;
        }

        oe_spin_unlock(&_lock);
    }
done:
    return result;
}

/**
 * This is the preferred way to call enclave functions.
 */
oe_result_t oe_handle_call_enclave_function(uint64_t arg_in)
{
    oe_call_enclave_function_args_t args, *args_ptr;
    oe_result_t result = OE_OK;
    oe_ecall_func_t func = NULL;
    uint8_t* buffer = NULL;
    uint8_t* input_buffer = NULL;
    uint8_t* output_buffer = NULL;
    size_t buffer_size = 0;
    size_t output_bytes_written = 0;
    ecall_table_t ecall_table;

    // Ensure that args lies outside the enclave.
    if (!oe_is_outside_enclave(
            (void*)arg_in, sizeof(oe_call_enclave_function_args_t)))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Copy args to enclave memory to avoid TOCTOU issues.
    args_ptr = (oe_call_enclave_function_args_t*)arg_in;
    args = *args_ptr;

    // Ensure that input buffer is valid.
    // Input buffer must be able to hold atleast an oe_result_t.
    if (args.input_buffer == NULL ||
        args.input_buffer_size < sizeof(oe_result_t) ||
        !oe_is_outside_enclave(args.input_buffer, args.input_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Ensure that output buffer is valid.
    // Output buffer must be able to hold atleast an oe_result_t.
    if (args.output_buffer == NULL ||
        args.output_buffer_size < sizeof(oe_result_t) ||
        !oe_is_outside_enclave(args.output_buffer, args.output_buffer_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    // Validate output and input buffer sizes.
    // Buffer sizes must be correctly aligned.
    if ((args.input_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((args.output_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_safe_add_u64(
        args.input_buffer_size, args.output_buffer_size, &buffer_size));

    // Resolve which ecall table to use.
    if (args_ptr->table_id == OE_UINT64_MAX)
    {
        ecall_table.ecalls = __oe_ecalls_table;
        ecall_table.num_ecalls = __oe_ecalls_table_size;
    }
    else
    {
        if (args_ptr->table_id >= OE_MAX_ECALL_TABLES)
            OE_RAISE(OE_NOT_FOUND);

        ecall_table.ecalls = _ecall_tables[args_ptr->table_id].ecalls;
        ecall_table.num_ecalls = _ecall_tables[args_ptr->table_id].num_ecalls;

        if (!ecall_table.ecalls)
            OE_RAISE(OE_NOT_FOUND);
    }

    // Fetch matching function.
    if (args.function_id >= ecall_table.num_ecalls)
        OE_RAISE(OE_NOT_FOUND);

    func = ecall_table.ecalls[args.function_id];

    if (func == NULL)
        OE_RAISE(OE_NOT_FOUND);

    // Allocate buffers in enclave memory
    buffer = input_buffer = oe_malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy input buffer to enclave buffer.
    memcpy(input_buffer, args.input_buffer, args.input_buffer_size);

    // Clear out output buffer.
    // This ensures reproducible behavior if say the function is reading from
    // output buffer.
    output_buffer = buffer + args.input_buffer_size;
    memset(output_buffer, 0, args.output_buffer_size);

    // Call the function.
    func(
        input_buffer,
        args.input_buffer_size,
        output_buffer,
        args.output_buffer_size,
        &output_bytes_written);

    // The output_buffer is expected to point to a marshaling struct,
    // whose first field is an oe_result_t. The function is expected
    // to fill this field with the status of the ecall.
    result = *(oe_result_t*)output_buffer;

    if (result == OE_OK)
    {
        // Copy outputs to host memory.
        memcpy(args.output_buffer, output_buffer, output_bytes_written);

        // The ecall succeeded.
        args_ptr->output_bytes_written = output_bytes_written;
        args_ptr->result = OE_OK;
    }

done:
    if (buffer)
        oe_free(buffer);

    return result;
}

/*
**==============================================================================
**
** _handle_exit()
**
**     Initiate call to EEXIT.
**
**==============================================================================
*/
static void _handle_exit(oe_code_t code, uint16_t func, uint64_t arg)
    OE_NO_RETURN;

static void _handle_exit(oe_code_t code, uint16_t func, uint64_t arg)
{
    oe_exit_enclave(oe_make_call_arg1(code, func, 0, OE_OK), arg);
}

void oe_virtual_exception_dispatcher(
    oe_sgx_td_t* td,
    uint64_t arg_in,
    uint64_t* arg_out);

/*
**==============================================================================
**
** _handle_ecall()
**
**     Handle an ECALL.
**
**==============================================================================
*/

static void _handle_ecall(
    oe_sgx_td_t* td,
    uint16_t func,
    uint64_t arg_in,
    uint64_t* output_arg1,
    uint64_t* output_arg2)
{
    /* To keep status of td consistent before and after _handle_ecall, td_init
     is moved into _handle_ecall. In this way _handle_ecall will not trigger
     stack check fail by accident. Of couse not all function have the
     opportunity to keep such consistency. Such basic functions are moved to a
     separate source file and the stack protector is disabled by force
     through fno-stack-protector option. */

    /* Initialize thread data structure (if not already initialized) */
    if (!td_initialized(td))
    {
        td_init(td);
    }

    oe_result_t result = OE_OK;

    /* Insert ECALL context onto front of oe_sgx_td_t.ecalls list */
    Callsite callsite = {{0}};
    uint64_t arg_out = 0;

    td_push_callsite(td, &callsite);

    // Acquire release semantics for __oe_initialized are present in
    // _handle_init_enclave.
    if (!__oe_initialized)
    {
        // The first call to the enclave must be to initialize it.
        // Global constructors can throw exceptions/signals and result in signal
        // handlers being invoked. Eg. Using CPUID instruction within a global
        // constructor. We should also allow handling these exceptions.
        if (func != OE_ECALL_INIT_ENCLAVE &&
            func != OE_ECALL_VIRTUAL_EXCEPTION_HANDLER)
        {
            goto done;
        }
    }
    else
    {
        // Disallow re-initialization.
        if (func == OE_ECALL_INIT_ENCLAVE)
        {
            goto done;
        }
    }

    // td_push_callsite increments the depth. depth > 1 indicates a reentrant
    // call. Reentrancy is allowed to handle exceptions and to terminate the
    // enclave.
    if (td->depth > 1 && (func != OE_ECALL_VIRTUAL_EXCEPTION_HANDLER &&
                          func != OE_ECALL_DESTRUCTOR))
    {
        /* reentrancy not permitted. */
        result = OE_REENTRANT_ECALL;
        goto done;
    }

    /* Dispatch the ECALL */
    switch (func)
    {
        case OE_ECALL_CALL_ENCLAVE_FUNCTION:
        {
            arg_out = oe_handle_call_enclave_function(arg_in);
            break;
        }
        case OE_ECALL_DESTRUCTOR:
        {
            /* Call functions installed by oe_cxa_atexit() and oe_atexit() */
            oe_call_atexit_functions();

            /* Call all finalization functions */
            oe_call_fini_functions();

#if defined(OE_USE_DEBUG_MALLOC)

            /* If memory still allocated, print a trace and return an error */
            if (!oe_disable_debug_malloc_check && oe_debug_malloc_check() != 0)
                result = OE_MEMORY_LEAK;

#endif /* defined(OE_USE_DEBUG_MALLOC) */

            /* Cleanup the allocator */
            oe_allocator_cleanup();

            break;
        }
        case OE_ECALL_VIRTUAL_EXCEPTION_HANDLER:
        {
            oe_virtual_exception_dispatcher(td, arg_in, &arg_out);
            break;
        }
        case OE_ECALL_INIT_ENCLAVE:
        {
            arg_out = _handle_init_enclave(arg_in);
            break;
        }
        default:
        {
            /* No function found with the number */
            result = OE_NOT_FOUND;
            goto done;
        }
    }

done:

    /* Free shared memory arena before we clear TLS */
    if (td->depth == 1)
    {
        oe_teardown_arena();
    }

    /* Remove ECALL context from front of oe_sgx_td_t.ecalls list */
    td_pop_callsite(td);

    /* Perform ERET, giving control back to host */
    *output_arg1 = oe_make_call_arg1(OE_CODE_ERET, func, 0, result);
    *output_arg2 = arg_out;
}

/*
**==============================================================================
**
** _handle_oret()
**
**     Handle an OCALL return.
**
**==============================================================================
*/

OE_INLINE void _handle_oret(
    oe_sgx_td_t* td,
    uint16_t func,
    uint16_t result,
    uint64_t arg)
{
    Callsite* callsite = td->callsites;

    if (!callsite)
        return;

    td->oret_func = func;
    td->oret_result = result;
    td->oret_arg = arg;

    oe_longjmp(&callsite->jmpbuf, 1);
}

/*
**==============================================================================
**
** oe_get_enclave_status()
**
**     Return the value of __oe_enclave_status to external code.
**
**==============================================================================
*/
oe_result_t oe_get_enclave_status()
{
    return __oe_enclave_status;
}

/*
**==============================================================================
**
** _exit_enclave()
**
** Exit the enclave.
** Additionally, if a debug enclave, write the exit frame information to host's
** ecall_context so that the host can stitch the ocall stack.
**
** This function is intended to be called by oe_asm_exit (see below).
** When called, the call stack would look like this:
**
**     enclave-function
**       -> oe_ocall
**         -> oe_exit_enclave (aliased as __morestack)
**           -> _exit_enclave
**
** For debug enclaves, _exit_enclave reads its caller (oe_exit_enclave/
** __morestack) information (return address, rbp) and passes it along to the
** host in the ecall_context.
**
** Then it proceeds to exit the enclave by invoking oe_asm_exit.
** oe_asm_exit invokes eexit instruction which resumes execution in host at the
** oe_enter function. The host dispatches the ocall via the following sequence:
**
**     oe_enter
**       -> __oe_host_stack_bridge   (Stitches the ocall stack)
**         -> __oe_dispatch_ocall
**           -> invoke ocall function
**
** Now that the enclave exit frame is available to the host,
** __oe_host_stack_bridge temporarily modifies its caller info with the
** enclave's exit information so that the stitched stack looks like this:
**
**     enclave-function                                    |
**       -> oe_ocall                                       |
**         -> oe_exit_enclave (aliased as __morestack)     | in enclave
**   --------------------------------------------------------------------------
**           -> __oe_host_stack_bridge                     | in host
**             -> __oe_dispatch_ocall                      |
**               -> invoke ocall function                  |
**
** This stitching of the stack is temporary, and __oe_host_stack_bridge reverts
** it prior to returning to its caller.
**
** Since the stitched (split) stack is preceded by the __morestack function, gdb
** natively walks the stack correctly.
**
**==============================================================================
*/
OE_NEVER_INLINE
OE_NO_RETURN
static void _exit_enclave(uint64_t arg1, uint64_t arg2)
{
    static bool _initialized = false;
    static bool _stitch_ocall_stack = false;
    oe_sgx_td_t* td = oe_sgx_get_td();

    // Since determining whether an enclave supports debugging is a stateless
    // idempotent operation, there is no need to lock. The result is cached
    // for performance since is_enclave_debug_allowed uses local report to
    // securely determine if an enclave supports debugging or not.
    if (!_initialized)
    {
        _stitch_ocall_stack = is_enclave_debug_allowed();
        _initialized = true;
    }

    if (_stitch_ocall_stack)
    {
        oe_ecall_context_t* host_ecall_context = td->host_ecall_context;

        // Make sure the context is valid.
        if (host_ecall_context &&
            oe_is_outside_enclave(
                host_ecall_context, sizeof(*host_ecall_context)))
        {
            uint64_t* frame = (uint64_t*)__builtin_frame_address(0);
            host_ecall_context->debug_eexit_rbp = frame[0];
            // The caller's RSP is always given by this equation
            //   RBP + 8 (caller frame pointer) + 8 (caller return address)
            host_ecall_context->debug_eexit_rsp = frame[0] + 8;
            host_ecall_context->debug_eexit_rip = frame[1];
        }
    }
    oe_asm_exit(arg1, arg2, td);
}

/*
**==============================================================================
**
** This function is wrapper of oe_asm_exit. It is needed to stitch the host
** stack and enclave stack together. It calls oe_asm_exit via an intermediary
** (_exit_enclave) that records the exit frame for ocall stack stitching.
**
** N.B: Don't change the function name, otherwise debugger can't work. GDB
** depends on this hardcoded function name when does stack walking for split
** stack. oe_exit_enclave has been #defined as __morestack.
**==============================================================================
*/

OE_NEVER_INLINE
void oe_exit_enclave(uint64_t arg1, uint64_t arg2)
{
    _exit_enclave(arg1, arg2);

    // This code is never reached. It exists to prevent tail call optimization
    // of the call to _exit_enclave. Tail-call optimization would effectively
    // inline _exit_enclave, and its caller would be come the caller of
    // oe_exit_enclave instead of oe_exit_enclave.
    oe_abort();
}

/*
**==============================================================================
**
** oe_ocall()
**
**     Initiate a call into the host (exiting the enclave).
**
** Remark: Given that the logging implementation relies on making an ocall to
** host, any failures when handling oe_ocall should not invoke any oe_log
** functions so as to avoid infinite recursion. OE_RAISE and OE_CHECK macros
** call oe_log functions, and therefore the following code locations use
** OE_RAISE_NO_TRACE and OE_CHECK_NO_TRACE macros.
**==============================================================================
*/

oe_result_t oe_ocall(uint16_t func, uint64_t arg_in, uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_td_t* td = oe_sgx_get_td();
    Callsite* callsite = td->callsites;

    /* If the enclave is in crashing/crashed status, new OCALL should fail
    immediately. */
    if (__oe_enclave_status != OE_OK)
        OE_RAISE_NO_TRACE((oe_result_t)__oe_enclave_status);

    /* Check for unexpected failures */
    if (!callsite)
        OE_RAISE_NO_TRACE(OE_UNEXPECTED);

    /* Check for unexpected failures */
    if (!td_initialized(td))
        OE_RAISE_NO_TRACE(OE_FAILURE);

    /* Save call site where execution will resume after OCALL */
    if (oe_setjmp(&callsite->jmpbuf) == 0)
    {
        /* Exit, giving control back to the host so it can handle OCALL */
        _handle_exit(OE_CODE_OCALL, func, arg_in);

        /* Unreachable! Host will transfer control back to oe_enter() */
        oe_abort();
    }
    else
    {
        OE_CHECK_NO_TRACE(result = (oe_result_t)td->oret_result);

        if (arg_out)
            *arg_out = td->oret_arg;

        /* ORET here */
    }

    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** oe_call_host_function_by_table_id()
**
**==============================================================================
*/

oe_result_t oe_call_host_function_by_table_id(
    uint64_t table_id,
    uint64_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written,
    bool switchless)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_function_args_t* args = NULL;

    /* Reject invalid parameters */
    if (!input_buffer || input_buffer_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /*
     * oe_post_switchless_ocall (below) can make a regular ocall to wake up the
     * host worker thread, and will end up using the ecall context's args.
     * Therefore, for switchless calls, allocate args in the arena so that it is
     * is not overwritten by oe_post_switchless_ocall.
     */
    args =
        (oe_call_host_function_args_t*)(switchless ? oe_arena_malloc(sizeof(*args)) : oe_ecall_context_get_ocall_args());

    if (args == NULL)
    {
        /* Fail if the enclave is crashing. */
        OE_CHECK(__oe_enclave_status);
        OE_RAISE(OE_UNEXPECTED);
    }

    args->table_id = table_id;
    args->function_id = function_id;
    args->input_buffer = input_buffer;
    args->input_buffer_size = input_buffer_size;
    args->output_buffer = output_buffer;
    args->output_buffer_size = output_buffer_size;
    args->result = OE_UNEXPECTED;

    /* Call the host function with this address */
    if (switchless && oe_is_switchless_initialized())
    {
        oe_result_t post_result = oe_post_switchless_ocall(args);

        // Fall back to regular OCALL if host worker threads are unavailable
        if (post_result == OE_CONTEXT_SWITCHLESS_OCALL_MISSED)
            OE_CHECK(
                oe_ocall(OE_OCALL_CALL_HOST_FUNCTION, (uint64_t)args, NULL));
        else
        {
            OE_CHECK(post_result);
            // Wait until args.result is set by the host worker.
            while (true)
            {
                OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
                if (__atomic_load_n(&args->result, __ATOMIC_SEQ_CST) !=
                    __OE_RESULT_MAX)
                    break;

                /* Yield to CPU */
                asm volatile("pause");
            }
        }
    }
    else
    {
        OE_CHECK(oe_ocall(OE_OCALL_CALL_HOST_FUNCTION, (uint64_t)args, NULL));
    }

    /* Check the result */
    OE_CHECK(args->result);

    *output_bytes_written = args->output_bytes_written;
    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** oe_call_host_function()
** This is the preferred way to call host functions.
**
**==============================================================================
*/

oe_result_t oe_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_host_function_by_table_id(
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written,
        false /* non-switchless */);
}

/*
**==============================================================================
**
** __oe_handle_main()
**
**     This function is called by oe_enter(), which is called by the EENTER
**     instruction (executed by the host). The host passes the following
**     parameters to EENTER:
**
**         RBX - TCS - address of a TCS page in the enclave
**         RCX - AEP - pointer to host's asynchronous exception procedure
**         RDI - ARGS1 (holds the CODE and FUNC parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     EENTER then calls oe_enter() with the following registers:
**
**         RAX - CSSA - index of current SSA
**         RBX - TCS - address of TCS
**         RCX - RETADDR - address to jump back to on EEXIT
**         RDI - ARGS1 (holds the code and func parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     Finally oe_enter() calls this function with the following parameters:
**
**         ARGS1 (holds the code and func parameters)
**         ARGS2 (holds the pointer to the args structure)
**         CSSA - index of current SSA
**         TCS - address of TCS (thread control structure)
**
**     Each enclave contains one or more thread sections (a collection of pages
**     used by a thread entering the enclave). Each thread section has the
**     following layout:
**
**         +----------------------------+
**         | Guard Page                 |
**         +----------------------------+
**         | Stack pages                |
**         +----------------------------+
**         | Guard Page                 |
**         +----------------------------+
**         | TCS Page                   |
**         +----------------------------+
**         | SSA (State Save Area) 0    |
**         +----------------------------+
**         | SSA (State Save Area) 1    |
**         +----------------------------+
**         | Guard Page                 |
**         +----------------------------+
**         | Thread local storage       |
**         +----------------------------+
**         | FS/GS Page (oe_sgx_td_t + tsp)    |
**         +----------------------------+
**
**     EENTER sets the FS segment register to refer to the FS page before
**     calling this function.
**
**     If the enclave should fault, SGX saves the registers in the SSA slot
**     (given by CSSA) and invokes the host's asynchronous exception handler
**     (AEP). The handler may terminate or call ERESUME which increments CSSA
**     and enters this function again. So:
**
**         CSSA == 0: indicates a normal entry
**         CSSA >= 1: indicates an exception entry
**
**     Since the enclave builder only allocates two SSA pages, the enclave can
**     nest no more than two faults. EENTER fails when the number of SSA slots
**     are exhausted (i.e., TCS.CSSA == TCS.NSSA)
**
**     This function ultimately calls EEXIT to exit the enclave. An enclave may
**     exit to the host for two reasons (aside from an asynchronous exception
**     already mentioned):
**
**         (1) To return normally from an ECALL
**         (2) To initiate an OCALL
**
**     When exiting to perform an OCALL, the host may perform another ECALL,
**     and so ECALLS and OCALLS may be nested arbitrarily until stack space is
**     exhausted (hitting a guard page). The state for performing nested calls
**     is maintained on the stack associated with the TCS (see diagram above).
**
**     The enclave's stack pointer is determined as follows:
**
**         (*) For non-nested calls, the stack pointer is calculated relative
**             to the TCS (one page before minus the STATIC stack size).
**
**         (*) For nested calls the stack pointer is obtained from the
**             oe_sgx_td_t.last_sp field (saved by the previous call).
**
**==============================================================================
*/
void __oe_handle_main(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs,
    uint64_t* output_arg1,
    uint64_t* output_arg2)
{
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    uint16_t func = oe_get_func_from_call_arg1(arg1);
    uint16_t arg1_result = oe_get_result_from_call_arg1(arg1);
    uint64_t arg_in = arg2;
    *output_arg1 = 0;
    *output_arg2 = 0;

    // Block enclave enter based on current enclave status.
    switch (__oe_enclave_status)
    {
        case OE_OK:
        {
            break;
        }
        case OE_ENCLAVE_ABORTING:
        {
            // Block any ECALL except first time OE_ECALL_DESTRUCTOR call.
            // Don't block ORET here.
            if (code == OE_CODE_ECALL)
            {
                if (func == OE_ECALL_DESTRUCTOR)
                {
                    // Termination function should be only called once.
                    __oe_enclave_status = OE_ENCLAVE_ABORTED;
                }
                else
                {
                    // Return crashing status.
                    *output_arg1 =
                        oe_make_call_arg1(OE_CODE_ERET, func, 0, OE_OK);
                    *output_arg2 = __oe_enclave_status;
                    return;
                }
            }

            break;
        }
        default:
        {
            // Return crashed status.
            *output_arg1 = oe_make_call_arg1(OE_CODE_ERET, func, 0, OE_OK);
            *output_arg2 = OE_ENCLAVE_ABORTED;
            return;
        }
    }

    // Initialize the enclave the first time it is ever entered. Note that
    // this function DOES NOT call global constructors. Global construction
    // is performed while handling OE_ECALL_INIT_ENCLAVE.
    oe_initialize_enclave();

    /* Get pointer to the thread data structure */
    oe_sgx_td_t* td = td_from_tcs(tcs);

    /* If this is a normal (non-exception) entry */
    if (cssa == 0)
    {
        switch (code)
        {
            case OE_CODE_ECALL:
                _handle_ecall(td, func, arg_in, output_arg1, output_arg2);
                break;

            case OE_CODE_ORET:
                /* Eventually calls oe_exit_enclave() and never returns here if
                 * successful */
                _handle_oret(td, func, arg1_result, arg_in);
                // fallthrough

            default:
                /* Unexpected case */
                oe_abort();
        }
    }
    else /* cssa > 0 */
    {
        if ((code == OE_CODE_ECALL) &&
            (func == OE_ECALL_VIRTUAL_EXCEPTION_HANDLER))
        {
            _handle_ecall(td, func, arg_in, output_arg1, output_arg2);
            return;
        }

        /* ATTN: handle asynchronous exception (AEX) */
        oe_abort();
    }
}

void oe_abort(void)
{
    // Once it starts to crash, the state can only transit forward, not
    // backward.
    if (__oe_enclave_status < OE_ENCLAVE_ABORTING)
    {
        __oe_enclave_status = OE_ENCLAVE_ABORTING;
    }

    // Free the shared memory pools
    oe_teardown_arena();

    // Return to the latest ECALL.
    _handle_exit(OE_CODE_ERET, 0, __oe_enclave_status);
}
