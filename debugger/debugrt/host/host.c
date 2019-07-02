// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/debugrt/host.h>
#include <string.h>

/**
 * In Windows, debugrt is built as a separate DLL that
 * OE host applications call into. Hence, this module cannot
 * use functionality (e.g spinlocks) defined in oehost.
 */

#ifdef _MSC_VER

#include <Windows.h>

static uint64_t _lock = 0;

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

#elif defined __GNUC__

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

/*
** These functions are needed to notify the debugger. They should not be
** optimized out even though they don't do anything in here.
*/

OE_NO_OPTIMIZE_BEGIN

OE_EXPORT
OE_NEVER_INLINE void oe_notify_gdb_enclave_creation(
    const oe_debug_enclave_t* enclave)
{
    OE_UNUSED(enclave);
    return;
}

OE_NEVER_INLINE void oe_notify_gdb_enclave_termination(
    const oe_debug_enclave_t* enclave)
{
    OE_UNUSED(enclave);
    return;
}

OE_NO_OPTIMIZE_END

#else

// Unsupported compiler and/or platform

#endif

oe_debug_enclave_t* oe_debug_enclaves_list = NULL;

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

#ifdef __linux__
    oe_notify_gdb_enclave_creation(enclave);
#endif

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
        result = OE_FAILURE;
        goto done;
    }

    *itr = enclave->next;
    enclave->next = NULL;
    result = OE_OK;

#ifdef __linux__
    oe_notify_gdb_enclave_termination(enclave);
#endif

done:
    if (locked)
        spin_unlock();

    return result;
}
