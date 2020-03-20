// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "atexit.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/thread.h>
#include "oe_nodebug_alloc.h"

/*
**==============================================================================
**
** oe_atexit_entry_t
**
**     This structure defines fields for an at-exit function and it's argument.
**     Instances of these are maintained on a list on the heap in reverse order.
**
**==============================================================================
*/

typedef struct _oe_atexit_entry oe_atexit_entry_t;

struct _oe_atexit_entry
{
    oe_atexit_entry_t* next;
    void (*func)(void*);
    void* arg;
};

static oe_atexit_entry_t* _entries;
static oe_spinlock_t _spin = OE_SPINLOCK_INITIALIZER;

/*
**==============================================================================
**
** _new_atexit_entry()
**
**     Allocate an oe_atexit_entry_t structure from the heap,
**     using oe_nodebug_malloc().
**
**==============================================================================
*/

static oe_atexit_entry_t* _new_atexit_entry(void (*func)(void*), void* arg)
{
    oe_atexit_entry_t* entry;

    if ((entry = (oe_atexit_entry_t*)oe_nodebug_malloc(
             sizeof(oe_atexit_entry_t))) == (void*)-1)
        return NULL;

    entry->func = func;
    entry->arg = arg;

    return entry;
}

/*
**==============================================================================
**
** oe_cxa_atexit()
**
**     Installs a function to be invoked upon exit (enclave termination).
**
**     The implementation injects an oe_atexit_entry_t structure onto a list
**     in reverse order (at the front of the list).
**
**==============================================================================
*/

int oe_cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    oe_atexit_entry_t* entry;
    OE_UNUSED(dso_handle);

    if (!(entry = _new_atexit_entry(func, arg)))
        return -1;

    /* Insert entry at the beginning of the list (reverse order) */
    oe_spin_lock(&_spin);
    {
        entry->next = _entries;
        _entries = entry;
    }
    oe_spin_unlock(&_spin);

    return 0;
}

/*
**==============================================================================
**
** oe_atexit()
**
**     Add a function to the at-exit list. It will be invoked upon enclave
**     termination by oe_call_atexit_functions().
**
**==============================================================================
*/

int oe_atexit(void (*function)(void))
{
    typedef void (*Function)(void*);

    /* Cast a function that takes no arguments to a function that takes a
     * single argument. Note that when function() is called, a null argument
     * is pushed on the stack but then ignored by function(), which expects
     * no arguments.
     */
    return oe_cxa_atexit((Function)function, NULL, NULL);
}

/*
**==============================================================================
**
** oe_call_atexit_functions()
**
**     This function invokes all at-exit functions.
**
**==============================================================================
*/

void oe_call_atexit_functions(void)
{
    oe_atexit_entry_t* p;

    /* Call at-exit functions in reverse order */
    for (p = _entries; p; p = p->next)
    {
        if (p->func)
            (*p->func)(p->arg);
    }
}
