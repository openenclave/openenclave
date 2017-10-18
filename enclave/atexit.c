#include "atexit.h"
#include <openenclave/enclave.h>

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/*
**==============================================================================
**
** OE_AtExitEntry
**
**     This structure defines fields for an at-exit routine and it's argument.
**     Instances of these are maintained on a list on the heap in reverse order.
**
**==============================================================================
*/

typedef struct _OE_AtExitEntry OE_AtExitEntry;

struct _OE_AtExitEntry
{
    OE_AtExitEntry* next;
    void (*func)(void*);
    void *arg;
};

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

    if (!(entry = (OE_AtExitEntry*)OE_Sbrk(sizeof(OE_AtExitEntry))))
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
**     This function is called to install a handler to be invoked upon exit.
**     Note that OE_CallConstructors() indirectly invokes this function for
**     each global C++ destructor as well.
**
**     The implementation injects OE_AtExitEntry structures onto a list
**     in reverse order.
**
**==============================================================================
*/

static OE_AtExitEntry* _entries;
static OE_Spinlock _spin = OE_SPINLOCK_INITIALIZER;

int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)
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
