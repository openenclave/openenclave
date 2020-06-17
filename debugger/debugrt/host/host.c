// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/debugrt/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * In Windows, debugrt is built as a separate DLL that
 * OE host applications call into. Hence, this module cannot
 * use functionality (e.g spinlocks) defined in oehost.
 */

#ifdef _MSC_VER

#include <Windows.h>

static volatile LONG _lock = 0;

static void spin_lock()
{
    while (InterlockedCompareExchange(&_lock, 1, 0) == 1)
    {
        // TODO: Do we need to yield CPU here?
        // Sleep(0);
    }
}

static void spin_unlock()
{
    InterlockedExchange(&_lock, 0);
}

static uint64_t get_current_thread_id()
{
    return (uint64_t)GetCurrentThreadId();
}

static bool raise_debugger_events()
{
    static bool initialized = false;

    if (IsDebuggerPresent())
    {
        if (!initialized)
        {
            // If specified, override oe_debugger_contract_version from the
            // environment.
            char* version;
            size_t getenv_length;
            getenv_s(&getenv_length, NULL, 0, "OE_DEBUGGER_CONTRACT_VERSION");

            if (getenv_length > 0)
            {
                version = (char*)malloc(sizeof(char) * getenv_length);
                getenv_s(
                    &getenv_length,
                    version,
                    sizeof(char) * getenv_length,
                    "OE_DEBUGGER_CONTRACT_VERSION");

                if (version != NULL)
                {
                    int v = 0;
                    if (sscanf_s(version, "%d", &v) == 1)
                    {
                        oe_debugger_contract_version = (uint32_t)v;
                    }
                }
            }

            initialized = true;
        }
        // Events are raised only if the contract is valid.
        return (oe_debugger_contract_version >= 1);
    }
    else
    {
        return false;
    }
}

void oe_notify_debugger_enclave_creation(const oe_debug_enclave_t* enclave)
{
    if (raise_debugger_events())
    {
        __try
        {
            ULONG_PTR args[1] = {(ULONG_PTR)enclave};
            RaiseException(
                OE_DEBUGRT_ENCLAVE_CREATED_EVENT,
                0, // dwFlags
                1, // number of args
                args);
        }
        __except (
            GetExceptionCode() == OE_DEBUGRT_ENCLAVE_CREATED_EVENT
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH)
        {
            // Debugger attached but did not handle the event.
            // Ignore and continue execution.
        }
    }
}

void oe_notify_debugger_enclave_termination(const oe_debug_enclave_t* enclave)
{
    if (raise_debugger_events())
    {
        __try
        {
            ULONG_PTR args[1] = {(ULONG_PTR)enclave};
            RaiseException(
                OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT,
                0, // dwFlags
                1, // number of args
                args);
        }
        __except (
            GetExceptionCode() == OE_DEBUGRT_ENCLAVE_TERMINATED_EVENT
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH)
        {
            // Debugger attached but did not handle the event.
            // Ignore and continue execution.
        }
    }
}

#elif defined __GNUC__

#include <pthread.h>

static uint8_t _lock = 0;

static void spin_lock()
{
    while (!__atomic_test_and_set(&_lock, __ATOMIC_SEQ_CST))
    {
        asm volatile("pause");
    }
}

static void spin_unlock()
{
    __atomic_clear(&_lock, __ATOMIC_SEQ_CST);
}

static uint64_t get_current_thread_id()
{
    return (uint64_t)pthread_self();
}

/*
** These functions are needed to notify the debugger. They should not be
** optimized out even though they don't do anything in here.
*/

OE_NO_OPTIMIZE_BEGIN

OE_EXPORT
OE_NEVER_INLINE void oe_notify_debugger_enclave_creation(
    const oe_debug_enclave_t* enclave)
{
    OE_UNUSED(enclave);
    return;
}

OE_NEVER_INLINE void oe_notify_debugger_enclave_termination(
    const oe_debug_enclave_t* enclave)
{
    OE_UNUSED(enclave);
    return;
}

OE_NO_OPTIMIZE_END

#else

#error Unsupported compiler and/or platform

#endif

/**
 * The version of the debugger contract supported by the runtime.
 * For development purposes, this value can be overridden by setting
 * the OE_DEBUGGER_CONTRACT_VERSION enviroment variable.
 */
uint32_t oe_debugger_contract_version = 1;

oe_debug_enclave_t* oe_debug_enclaves_list = NULL;
oe_debug_thread_binding_t* oe_debug_thread_bindings_list = NULL;

oe_result_t oe_debug_notify_enclave_created(oe_debug_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    bool locked = false;

    if (enclave == NULL || enclave->magic != OE_DEBUG_ENCLAVE_MAGIC)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    // Prepend enclave to the list.
    spin_lock();
    locked = true;

    enclave->next = oe_debug_enclaves_list;
    oe_debug_enclaves_list = enclave;

    result = OE_OK;

    oe_notify_debugger_enclave_creation(enclave);

done:
    if (locked)
        spin_unlock();

    return result;
}

oe_result_t oe_debug_notify_enclave_terminated(oe_debug_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    bool locked = false;

    if (enclave == NULL || enclave->magic != OE_DEBUG_ENCLAVE_MAGIC)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    spin_lock();
    locked = true;

    // Remove enclave from list
    oe_debug_enclave_t** itr = &oe_debug_enclaves_list;
    while (*itr)
    {
        if (*itr == enclave)
            break;
        itr = &(*itr)->next;
    }

    if (*itr == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    *itr = enclave->next;
    enclave->next = NULL;
    result = OE_OK;

    oe_notify_debugger_enclave_termination(enclave);

done:
    if (locked)
        spin_unlock();

    return result;
}

oe_result_t oe_debug_push_thread_binding(
    oe_debug_enclave_t* enclave,
    struct _sgx_tcs* tcs)
{
    oe_result_t result = OE_FAILURE;
    bool locked = false;
    oe_debug_thread_binding_t* binding = NULL;

    if (enclave == NULL || tcs == NULL)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    binding = (oe_debug_thread_binding_t*)malloc(sizeof(*binding));
    if (binding == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    spin_lock();
    locked = true;

    binding->magic = OE_DEBUG_THREAD_BINDING_MAGIC;
    binding->version = 1;
    binding->enclave = enclave;
    binding->tcs = tcs;
    binding->thread_id = get_current_thread_id();

    binding->next = oe_debug_thread_bindings_list;
    oe_debug_thread_bindings_list = binding;
    result = OE_OK;

done:
    if (locked)
        spin_unlock();

    return result;
}

oe_result_t oe_debug_pop_thread_binding()
{
    oe_result_t result = OE_FAILURE;
    bool locked = false;
    oe_debug_thread_binding_t* binding = NULL;

    uint64_t thread_id = get_current_thread_id();

    spin_lock();
    locked = true;

    oe_debug_thread_binding_t** itr = &oe_debug_thread_bindings_list;
    while (*itr)
    {
        if ((*itr)->thread_id == thread_id)
            break;
        itr = &(*itr)->next;
    }

    if (*itr == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    binding = *itr;
    *itr = binding->next;
    free(binding);
    result = OE_OK;

done:
    if (locked)
        spin_unlock();

    return result;
}
