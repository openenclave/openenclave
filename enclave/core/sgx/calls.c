// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/edger8r/switchless.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../../asym_keys.h"
#include "../../sgx/report.h"
#include "../atexit.h"
#include "asmdefs.h"
#include "cpuid.h"
#include "init.h"
#include "report.h"
#include "td.h"

oe_result_t __oe_enclave_status = OE_OK;
uint8_t __oe_initialized = 0;

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

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
**     td_t       - Thread data. Per thread data as defined by the
**                oe_thread_data_t structure and extended by the td_t structure.
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
        // Assert that arg_in is outside the enclave and is not null.
        if (!oe_is_outside_enclave(
                (void*)arg_in, sizeof(oe_init_enclave_args_t)))
        {
            OE_RAISE(OE_INVALID_PARAMETER);
        }

        static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
        oe_spin_lock(&_lock);

        if (_once == false)
        {
            /* Install the internal ecall function table. */
            OE_CHECK(oe_register_internal_ecall_function_table());

            /* Set the global enclave handle */
            oe_init_enclave_args_t* args = (oe_init_enclave_args_t*)arg_in;
            oe_init_enclave_args_t safe_args;

            if (!oe_is_outside_enclave(args, sizeof(*args)))
                OE_RAISE(OE_INVALID_PARAMETER);

            /* Copy structure into enclave memory */
            safe_args = *args;

            if (!oe_is_outside_enclave(safe_args.enclave, 1))
                OE_RAISE(OE_INVALID_PARAMETER);

            oe_enclave = safe_args.enclave;

            /* Call all enclave state initialization functions */
            OE_CHECK(oe_initialize_cpuid(&safe_args));

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
 * The __oe_ecalls_table table is expected to be generated by oeedger8r
 */
extern const oe_ecall_func_t __oe_ecalls_table[];
extern const size_t __oe_ecalls_table_size;

/*
**==============================================================================
**
** oe_register_ecall_function_table()
**
** Register an ecall table with the given table_id.
**
**==============================================================================
*/

typedef struct _ecall_table
{
    const oe_ecall_func_t* ecalls;
    size_t num_ecalls;
} ecall_table_t;

static ecall_table_t _ecall_tables[OE_MAX_ECALL_TABLES];
static oe_spinlock_t _ecall_tables_lock = OE_SPINLOCK_INITIALIZER;

oe_result_t oe_register_ecall_function_table(
    uint64_t table_id,
    const oe_ecall_func_t* ecalls,
    size_t num_ecalls)
{
    oe_result_t result = OE_UNEXPECTED;

    if (table_id >= OE_MAX_ECALL_TABLES || !ecalls)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_spin_lock(&_ecall_tables_lock);
    _ecall_tables[table_id].ecalls = ecalls;
    _ecall_tables[table_id].num_ecalls = num_ecalls;
    oe_spin_unlock(&_ecall_tables_lock);

    result = OE_OK;

done:
    return result;
}

static oe_result_t _handle_ecall_function(
    uint64_t table_id,
    uint64_t function_id,
    const uint8_t* host_input_buffer,
    size_t input_buffer_size,
    uint8_t* host_output_buffer,
    size_t output_buffer_size,
    size_t* host_output_bytes_written,
    oe_result_t* host_result)
{
    oe_result_t result = OE_OK;
    uint8_t* buffer = NULL;
    size_t buffer_size = 0;
    uint8_t* enc_input_buffer = NULL;
    uint8_t* enc_output_buffer = NULL;
    size_t enc_output_bytes_written = 0;
    ecall_table_t ecall_table;
    oe_ecall_func_t func = NULL;

    // Ensure that input buffer is valid.
    // Input buffer must be able to hold atleast an oe_result_t.
    if (host_input_buffer == NULL || input_buffer_size < sizeof(oe_result_t) ||
        !oe_is_outside_enclave(host_input_buffer, input_buffer_size))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Ensure that output buffer is valid.
    // Output buffer must be able to hold atleast an oe_result_t.
    if (host_output_buffer == NULL ||
        output_buffer_size < sizeof(oe_result_t) ||
        !oe_is_outside_enclave(host_output_buffer, output_buffer_size))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    // Validate output and input buffer sizes.
    // Buffer sizes must be correctly aligned.
    if ((input_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    if ((output_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    OE_CHECK(
        oe_safe_add_u64(input_buffer_size, output_buffer_size, &buffer_size));

    // Resolve which ecall table to use.
    if (OE_UINT64_MAX == table_id)
    {
        ecall_table.ecalls = __oe_ecalls_table;
        ecall_table.num_ecalls = __oe_ecalls_table_size;
    }
    else
    {
        if (table_id >= OE_MAX_ECALL_TABLES)
        {
            OE_RAISE(OE_NOT_FOUND);
        }

        ecall_table.ecalls = _ecall_tables[table_id].ecalls;
        ecall_table.num_ecalls = _ecall_tables[table_id].num_ecalls;

        if (!ecall_table.ecalls)
        {
            OE_RAISE(OE_NOT_FOUND);
        }
    }

    // Fetch matching function.
    if (function_id >= ecall_table.num_ecalls)
    {
        OE_RAISE(OE_NOT_FOUND);
    }

    func = ecall_table.ecalls[function_id];

    if (NULL == func)
    {
        OE_RAISE(OE_NOT_FOUND);
    }

    // Allocate buffers in enclave memory
    buffer = enc_input_buffer = oe_malloc(buffer_size);
    if (NULL == buffer)
    {
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    // Copy input buffer to enclave buffer.
    memcpy(enc_input_buffer, host_input_buffer, input_buffer_size);

    // Clear out output buffer.
    // This ensures reproducible behavior if say the function is reading from
    // output buffer.
    enc_output_buffer = buffer + input_buffer_size;
    memset(enc_output_buffer, 0, output_buffer_size);

    // Call the function.
    func(
        enc_input_buffer,
        input_buffer_size,
        enc_output_buffer,
        output_buffer_size,
        &enc_output_bytes_written);

    // The output_buffer is expected to point to a marshaling struct,
    // whose first field is an oe_result_t. The function is expected
    // to fill this field with the status of the ecall.
    result = *(oe_result_t*)enc_output_buffer;

    if (OE_OK == result)
    {
        // Copy outputs to host memory.
        memcpy(host_output_buffer, enc_output_buffer, enc_output_bytes_written);

        // The ecall succeeded.
        *host_output_bytes_written = enc_output_bytes_written;
        *host_result = OE_OK;
    }

done:
    if (buffer)
    {
        oe_free(buffer);
    }

    return result;
} /* _handle_ecall_function */

static oe_result_t _handle_call_enclave_function(uint64_t arg_in)
{
    oe_call_enclave_function_args_t* args_ptr =
        (oe_call_enclave_function_args_t*)arg_in;
    oe_result_t result = OE_OK;

    // Ensure that args lies outside the enclave.
    if (!oe_is_outside_enclave(
            (void*)arg_in, sizeof(oe_call_enclave_function_args_t)))
        OE_RAISE(OE_INVALID_PARAMETER);

    result = _handle_ecall_function(
        args_ptr->table_id,
        args_ptr->function_id,
        (const uint8_t*)args_ptr->input_buffer,
        args_ptr->input_buffer_size,
        args_ptr->output_buffer,
        args_ptr->output_buffer_size,
        &(args_ptr->output_bytes_written),
        &(args_ptr->result));

done:
    return result;
}

static oe_result_t _handle_synchronous_switchless_ecall(
    oe_switchless_synchronous_ecall_t* ecall)
{
    oe_result_t result = OE_UNEXPECTED;

    // Ensure that args lies outside the enclave.
    if (!oe_is_outside_enclave(
            (void*)ecall, sizeof(oe_switchless_synchronous_ecall_t)))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    result = _handle_ecall_function(
        ecall->table_id,
        ecall->function_id,
        ecall->input_buffer,
        ecall->input_buffer_size,
        ecall->output_buffer,
        ecall->output_buffer_size,
        &(ecall->output_bytes_written),
        &(ecall->result));

done:
    __atomic_store_n(&(ecall->lock), 0, __ATOMIC_RELEASE);

    return result;
} /* _handle_synchronous_switchless_ecall */

static oe_switchless_state_t _get_switchless_state(oe_switchless_t* switchless)
{
    oe_switchless_state_t state;
    state = __atomic_load_n(&(switchless->state), __ATOMIC_ACQUIRE);
    return state;
} /* _get_switchless_state */

static oe_result_t _handle_launch_enclave_worker(uint64_t arg_in)
{
    oe_result_t result = OE_FAILURE;
    oe_enc_switchless_worker_start_args_t* volatile args =
        (oe_enc_switchless_worker_start_args_t*)arg_in;
    oe_switchless_t* switchless = NULL;

    /* ensure that args lies outside the enclave */
    if (!oe_is_outside_enclave(
            args, sizeof(oe_enc_switchless_worker_start_args_t)) ||
        !oe_is_outside_enclave(args->switchless, sizeof(oe_switchless_t)))
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* arg_in will no longer be valid after the lock is released */
    switchless = args->switchless;
    args->result = OE_OK;
    __atomic_store_n(&(args->lock), 0, __ATOMIC_RELEASE);

    result = OE_OK;

    /* loop until the state changes to stopping */
    while (OE_SWITCHLESS_STATE_STOPPING != _get_switchless_state(switchless))
    {
        /* note: this pop needs to be protected by a lock if there is more than
         * one worker thread */
        oe_switchless_synchronous_ecall_t* ecall_node =
            (oe_switchless_synchronous_ecall_t*)oe_lockless_queue_pop_front(
                &(switchless->ecall_queue));
        if (NULL != ecall_node)
        {
            _handle_synchronous_switchless_ecall(ecall_node);
        }
    }

done:
    return result;
} /* _handle_launch_enclave_worker */

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
{
    oe_exit_enclave(oe_make_call_arg1(code, func, 0, OE_OK), arg);
}

void oe_virtual_exception_dispatcher(
    td_t* td,
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
    td_t* td,
    uint16_t func,
    uint64_t arg_in,
    uint64_t* output_arg1,
    uint64_t* output_arg2)
{
    oe_result_t result = OE_OK;

    /* Insert ECALL context onto front of td_t.ecalls list */
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
            arg_out = _handle_call_enclave_function(arg_in);
            break;
        }
        case OE_ECALL_DESTRUCTOR:
        {
            /* Call functions installed by __cxa_atexit() and oe_atexit() */
            oe_call_atexit_functions();

            /* Call all finalization functions */
            oe_call_fini_functions();

#if defined(OE_USE_DEBUG_MALLOC)

            /* If memory still allocated, print a trace and return an error */
            if (!oe_disable_debug_malloc_check && oe_debug_malloc_check() != 0)
                result = OE_MEMORY_LEAK;

#endif /* defined(OE_USE_DEBUG_MALLOC) */

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
        case OE_ECALL_GET_SGX_REPORT:
        {
            arg_out = _handle_get_sgx_report(arg_in);
            break;
        }
        case OE_ECALL_VERIFY_REPORT:
        {
            oe_handle_verify_report(arg_in, &arg_out);
            break;
        }
        case OE_ECALL_LOG_INIT:
        {
            _handle_oelog_init(arg_in);
            break;
        }
        case OE_ECALL_GET_PUBLIC_KEY_BY_POLICY:
        {
            oe_handle_get_public_key_by_policy(arg_in);
            break;
        }
        case OE_ECALL_GET_PUBLIC_KEY:
        {
            oe_handle_get_public_key(arg_in);
            break;
        }
        case OE_ECALL_LAUNCH_ENCLAVE_WORKER:
        {
            result = _handle_launch_enclave_worker(arg_in);
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

    /* Remove ECALL context from front of td_t.ecalls list */
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
    td_t* td,
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
    td_t* td = oe_get_td();
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
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_function_args_t* args = NULL;

    /* Reject invalid parameters */
    if (!input_buffer || input_buffer_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the arguments */
    {
        if (!(args = oe_host_calloc(1, sizeof(*args))))
        {
            /* Fail if the enclave is crashing. */
            OE_CHECK(__oe_enclave_status);
            OE_RAISE(OE_OUT_OF_MEMORY);
        }

        args->table_id = table_id;
        args->function_id = function_id;
        args->input_buffer = input_buffer;
        args->input_buffer_size = input_buffer_size;
        args->output_buffer = output_buffer;
        args->output_buffer_size = output_buffer_size;
        args->result = OE_UNEXPECTED;
    }

    /* Call the host function with this address */
    OE_CHECK(oe_ocall(OE_OCALL_CALL_HOST_FUNCTION, (uint64_t)args, NULL));

    /* Check the result */
    OE_CHECK(args->result);

    *output_bytes_written = args->output_bytes_written;
    result = OE_OK;

done:

    oe_host_free(args);

    return result;
}

typedef enum _loop_state {
    WRITING_INPUT_HEADER,
    WRITING_INPUT_BUFFER,
    WRITING_OUTPUT_BUFFER,
    WAITING_FOR_LOCK,
    READING_OUTPUT_HEADER,
    READING_INPUT_BUFFER,
    READING_OUTPUT_BUFFER,
    COMPLETE,
} loop_state_t;

oe_result_t oe_switchless_call_host_function_by_table_id(
    oe_switchless_t* switchless,
    uint64_t table_id,
    uint64_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    //oe_host_printf("<entering oe_switchless_call_host_function>\n");
    /* todo:
     *  there should be a lock around this because the lockless_ring_buffer, and
     *  the way that data is serialized and deserialized is not safe for
     *  multiple readers or multiple writers  (it is safe for a single reader
     *  and single writer to be conncurrent)
     *
     *  there is also a problem with the oe_switchless_t* pointer here.  the
     *  enclave needs to have access to this object.  for this demo, the
     *  switchless ocall is made from a switchless ecall.  this member probably
     *  needs to be engineered into the elf header so that the enclave has
     *  access to it.
     */
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_function_args_t input_header = {
        table_id,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        0,
        OE_FAILURE /* this value is not being changed and is being returned */
    };
    oe_call_host_function_args_t output_header;
    loop_state_t state = WRITING_INPUT_HEADER;
    size_t total_size = sizeof(oe_call_host_function_args_t);
    size_t current_size = 0;

    /* Reject invalid parameters */
    if (!input_buffer || input_buffer_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* worker loop
     * 1. write the oe_call_host_function_args
     * 2. write the input buffer
     * 3. write the output buffer
     * 4. read the oe_call_host_function_args
     * 5. read the input buffer (conditionally)
     * 6. read the output buffer (conditionally)
     */
    //oe_host_printf("<** WRITING_INPUT_HEADER>\n");
    
    /* when host_worker_lock == 0, the enclave can read
     * when host_worker_lock == 1, the host can read */
    __atomic_store_n(&(switchless->host_worker_lock), 1, __ATOMIC_RELEASE);
    
    while (OE_SWITCHLESS_STATE_STOPPING != _get_switchless_state(switchless) &&
           COMPLETE != state)
    {
        switch (state)
        {
        case WRITING_INPUT_HEADER:
        {
            size_t written =
                oe_lockless_ring_buffer_write(
                    switchless->ocall_buffer,
                    ((char*)&input_header) + current_size,
                    total_size - current_size);
            current_size += written;
            //if (0 < written)
            //{
            //    oe_host_printf(" **** written: %u ** current: %u ** total: %u\n",
            //                   (unsigned)written, (unsigned)current_size,
            //                   (unsigned)total_size);
            //}
            /* when the input header is finished writing */
            if (current_size == total_size)
            {
                //oe_host_printf("<** WRITING_INPUT_BUFFER>\n");
                state = WRITING_INPUT_BUFFER;
                total_size = input_buffer_size;
                current_size = 0;
            }
            break;
        }
        case WRITING_INPUT_BUFFER:
        {
            size_t written =
                oe_lockless_ring_buffer_write(
                    switchless->ocall_buffer,
                    ((char*)input_buffer) + current_size,
                    total_size - current_size);
            current_size += written;
            //if (0 < written)
            //{
            //    oe_host_printf(" **** written: %u ** current: %u ** total: %u\n",
            //                   (unsigned)written, (unsigned)current_size,
            //                   (unsigned)total_size);
            //}
            /* when the input buffer is finished writing */
            if (current_size == total_size)
            {
                //oe_host_printf("<** WRITING_OUTPUT_HEADER>\n");
                state = WRITING_OUTPUT_BUFFER;
                total_size = output_buffer_size;
                current_size = 0;
            }
            break;
        }
        case WRITING_OUTPUT_BUFFER:
        {
            /* do we really need to copy the output_buffer
             * that would require a corresponding change to _host_worker_thread
             * I didn't take time to see where in/out params are stored */
            size_t written =
                oe_lockless_ring_buffer_write(
                    switchless->ocall_buffer,
                    ((char*)output_buffer) + current_size,
                    total_size - current_size);
            current_size += written;
            //if (0 < written)
            //{
            //    oe_host_printf(" **** written: %u ** current: %u ** total: %u\n",
            //                   (unsigned)written, (unsigned)current_size,
            //                   (unsigned)total_size);
            //}
            /* when the output buffer is finished writing */
            if (current_size == total_size)
            {
                /* need to wait before reading from this buffer */
                //oe_host_printf("<** WAITING_FOR_LOCK>\n");
                state = WAITING_FOR_LOCK;
            }
            break;
        }
        case WAITING_FOR_LOCK:
        {
            /* when host_worker_lock == 0, the enclave can read
             * when host_worker_lock == 1, the host can read */
            if (0 == __atomic_load_n(
                    &(switchless->host_worker_lock), __ATOMIC_ACQUIRE))
            {
                //oe_host_printf("<** READING_OUTPUT_HEADER>\n");
                state = READING_OUTPUT_HEADER;
                total_size = sizeof(oe_call_host_function_args_t);
                current_size = 0;
            }
            break;
        }
        case READING_OUTPUT_HEADER:
        {
            size_t read =
                oe_lockless_ring_buffer_read(
                    switchless->ocall_buffer,
                    ((char*)&output_header) + current_size,
                    total_size - current_size);
            current_size += read;
            //if (0 < read)
            //{
            //    oe_host_printf(" **** read: %u ** current: %u ** total: %u\n",
            //                   (unsigned)read, (unsigned)current_size,
            //                   (unsigned)total_size);
            //}
            /* when the output header is finished reading */
            if (current_size == total_size)
            {
                result = input_header.result = output_header.result;
                /* verify that things match and the results were successful */
                if (OE_OK == output_header.result)
                {
                    if (input_buffer_size != output_header.input_buffer_size ||
                        output_buffer_size !=
                        output_header.output_buffer_size ||
                        output_buffer_size <
                        output_header.output_bytes_written)
                    {
                        //oe_host_printf("<** COMPLETE> (0) error %s\n",
                        //               oe_result_str(result));
                        result = OE_FAILURE;
                        state = COMPLETE;
                    }
                    else
                    {
                        //oe_host_printf("<** READING_INPUT_HEADER>\n");
                        state = READING_INPUT_BUFFER;
                        current_size = 0;
                        total_size = input_buffer_size;
                    }
                }
                else
                {
                    //oe_host_printf("<** COMPLETE> (1) error %s\n",
                    //               oe_result_str(result));
                    state = COMPLETE;
                }
            }
            break;
        }
        case READING_INPUT_BUFFER:
        {
            /* do we really need to copy the input_buffer
             * that would require a corresponding change to _host_worker_thread
             * I didn't take time to see where in/out params are stored */
            size_t read =
                oe_lockless_ring_buffer_read(
                    switchless->ocall_buffer,
                    ((char*)input_buffer) + current_size,
                    output_header.input_buffer_size - current_size);
            current_size += read;
            /* when the input buffer is finished reading */
            if (current_size == total_size)
            {
                //oe_host_printf("<** READING_OUTPUT_BUFFER>\n");
                state = READING_OUTPUT_BUFFER;
                total_size = output_buffer_size;
                current_size = 0;
            }
            break;
        }
        case READING_OUTPUT_BUFFER:
        {
            /* should this read bytes_written instead?
             * that would require a corresponding change to _host_worker_thread
             */
            size_t read =
                oe_lockless_ring_buffer_read(
                    switchless->ocall_buffer,
                    ((char*)output_buffer) + current_size,
                    output_header.output_buffer_size - current_size);
            current_size += read;
            /* when the input buffer is finished reading */
            if (current_size == total_size)
            {
                //oe_host_printf("<** COMPLETE>\n");
                state = COMPLETE;
                result = OE_OK;
            }
            break;
        }
        case COMPLETE:
            break;
        }
    }
    
    /* Check the result */
    OE_CHECK(output_header.result);

    *output_bytes_written = output_header.output_bytes_written;
    result = OE_OK;

done:

    //oe_host_printf("<exiting oe_switchless_call_host_function>\n");
    return result;
} /* oe_switchless_call_host_function_by_table_id */

oe_result_t oe_switchless_call_host_function(
    oe_switchless_t* switchless,
    uint64_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_switchless_call_host_function_by_table_id(
        switchless,
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
} /* oe_switchless_call_host_function */

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
        output_bytes_written);
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
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | Stack pages                    |
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | TCS Page                       |
**         +--------------------------------+
**         | SSA (State Save Area) 0        |
**         +--------------------------------+
**         | SSA (State Save Area) 1        |
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | GS page (contains thread data) |
**         +--------------------------------+
**
**     EENTER sets the GS segment register to refer to the GS page before
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
**             td_t.last_sp field (saved by the previous call).
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
    td_t* td = td_from_tcs(tcs);

    /* Initialize thread data structure (if not already initialized) */
    if (!td_initialized(td))
        td_init(td);

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

/*
**==============================================================================
**
** oe_notify_nested_exit_start()
**
**     Notify the nested exit happens.
**
**     This function saves the current ocall context to the thread data. The
**     ocall context contains the stack pointer and the return address of the
**     function when ocall happens inside enclave (i.e. one type of nested
**     exit).
**     When debugger does stack stitching, it will update the untrusted ocall
**     frame's previous stack frame pointer and return address with the ocall
**     context from trusted thread data. When GDB does stack walking, the parent
**     stack of an untrusted ocall will be stack of the _OE_EXIT trusted
**     function instead of stack of oe_enter/__morestack untrusted function.
**     Refer to the oe_notify_ocall_start function in host side, and the
**     OCallStartBreakpoint and update_untrusted_ocall_frame function in the
**     python plugin.
**
**==============================================================================
*/
void oe_notify_nested_exit_start(
    uint64_t arg1,
    oe_ocall_context_t* ocall_context)
{
    // Check if it is an OCALL.
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    if (code != OE_CODE_OCALL)
        return;

    // Save the ocall_context to the callsite of current enclave thread.
    td_t* td = oe_get_td();
    Callsite* callsite = td->callsites;
    callsite->ocall_context = ocall_context;

    return;
}

void oe_abort(void)
{
    // Once it starts to crash, the state can only transit forward, not
    // backward.
    if (__oe_enclave_status < OE_ENCLAVE_ABORTING)
    {
        __oe_enclave_status = OE_ENCLAVE_ABORTING;
    }

    // Return to the latest ECALL.
    _handle_exit(OE_CODE_ERET, 0, __oe_enclave_status);
    return;
}
