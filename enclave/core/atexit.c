// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/atexit.h>
#include <openenclave/enclave.h>

/*
**==============================================================================
**
** OE_AtExitEntry
**
**     This structure defines fields for an at-exit function and it's argument.
**     Instances of these are maintained on a list on the heap in reverse order.
**
**==============================================================================
*/

typedef struct _OE_AtExitEntry OE_AtExitEntry;

struct _OE_AtExitEntry
{
    OE_AtExitEntry* next;
    void (*func)(void*);
    void* arg;
};

static OE_AtExitEntry* _entries;
static OE_Spinlock _spin = OE_SPINLOCK_INITIALIZER;

/*
**==============================================================================
**
** _NewAtExitEntry()
**
**     Allocate an OE_AtExitEntry structure from the heap using sbrk().
**
**==============================================================================
*/

static OE_AtExitEntry* _NewAtExitEntry(void (*func)(void*), void* arg)
{
    OE_AtExitEntry* entry;

    if ((entry = (OE_AtExitEntry*)OE_Sbrk(sizeof(OE_AtExitEntry))) == (void*)-1)
        return NULL;

    entry->func = func;
    entry->arg = arg;

    return entry;
}

/*
**==============================================================================
**
** __cxa_atexit()
**
**     Installs a function to be invoked upon exit (enclave termination).
**
**     The implementation injects an OE_AtExitEntry structure onto a list
**     in reverse order (at the front of the list).
**
**==============================================================================
*/

int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    OE_AtExitEntry* entry;

    if (!(entry = _NewAtExitEntry(func, arg)))
        return -1;

    /* Insert entry at the beginning of the list (reverse order) */
    OE_SpinLock(&_spin);
    {
        entry->next = _entries;
        _entries = entry;
    }
    OE_SpinUnlock(&_spin);

    return 0;
}

/*
**==============================================================================
**
** OE_AtExit()
**
**     Add a function to the at-exit list. It will be invoked upon enclave
**     termination by OE_CallAtExitFunctions().
**
**==============================================================================
*/

int OE_AtExit(void (*function)(void))
{
    typedef void (*Function)(void*);

    /* Cast a function that takes no arguments to a function that takes a
     * single argument. Note that when function() is called, a null argument
     * is pushed on the stack but then ignored by function(), which expects
     * no arguments.
     */
    return __cxa_atexit((Function)function, NULL, NULL);
}

/*
**==============================================================================
**
** OE_CallAtExitFunctions()
**
**     This function invokes all at-exit functions.
**
**==============================================================================
*/

void OE_CallAtExitFunctions(void)
{
    OE_AtExitEntry* p;

    /* Call at-exit functions in reverse order */
    for (p = _entries; p; p = p->next)
    {
        if (p->func)
            (*p->func)(p->arg);
    }
}

/*
**==============================================================================
**
** atexit()
**
**     Enclave implementation of the libc atexit function.
**
**==============================================================================
*/

int atexit(void (*function)(void))
{
    return OE_AtExit(function);
}
