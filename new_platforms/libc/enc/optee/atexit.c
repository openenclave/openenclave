#define _GNU_SOURCE
#include <unistd.h>

typedef struct _oe_atexit_entry oe_atexit_entry_t;

struct _oe_atexit_entry
{
    oe_atexit_entry_t* next;
    void (*func)(void*);
    void* arg;
};

static oe_atexit_entry_t* _entries;

static oe_atexit_entry_t* _new_atexit_entry(void (*func)(void*), void* arg)
{
    oe_atexit_entry_t* entry;

    if ((entry = (oe_atexit_entry_t*)sbrk(sizeof(oe_atexit_entry_t))) ==
        (void*)-1)
        return NULL;

    entry->func = func;
    entry->arg = arg;

    return entry;
}

int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    oe_atexit_entry_t* entry;
    (void)(dso_handle);

    if (!(entry = _new_atexit_entry(func, arg)))
        return -1;

    /* Insert entry at the beginning of the list (reverse order) */
    entry->next = _entries;
    _entries = entry;

    return 0;
}

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
