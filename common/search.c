#include <openenclave/types.h>
#include <openenclave/bits/search.h>
#include <openenclave/thread.h>

#ifdef OE_BUILD_UNTRUSTED
# include <search.h>
#endif

static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

void *__OE_Tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *));

void __OE_Tdestroy(
    void *root, 
    void (*freekey)(void *nodep));

void *__OE_Tdelete(
    const void *restrict key, 
    void **restrict rootp,
    int(*compar)(const void *, const void *));

/* Rename VISIT enum and elements */
#define VISIT OE_VISIT
#define preorder OE_preorder
#define postorder OE_postorder
#define endorder OE_endorder
#define leaf OE_leaf 

/* Rename functions */
#define tdelete __OE_Tdelete
#define tfind OE_Tfind
#define tsearch __OE_Tsearch
#define twalk OE_Twalk

/* Redirect to call user-provided free and malloc */
#define free _OE_free
#define malloc _OE_malloc

static void* (*_alloc_callback)(size_t size, void* data);
static void* _alloc_callback_data;

static void* _OE_malloc(size_t size)
{
    if (_alloc_callback)
        return (*_alloc_callback)(size, _alloc_callback_data);

    return NULL;
}

static void (*_free_callback)(void* ptr);

static void _OE_free(void* ptr)
{
    if (_free_callback)
        (*_free_callback)(ptr);
}

#include "../3rdparty/musl/musl/src/search/tsearch_avl.c"

void *OE_Tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *),
    void* (*alloc)(size_t, void* data),
    void* data)
{
    OE_SpinLock(&_lock);
    _alloc_callback = alloc;
    _alloc_callback_data = data;
    void* ret = __OE_Tsearch(key, rootp, compar);
    _alloc_callback = (void*)0;
    _alloc_callback_data = NULL;
    OE_SpinUnlock(&_lock);

    return ret;
}

void *OE_Tdelete(
    const void *restrict key, 
    void **restrict rootp,
    int(*compar)(const void *, const void *),
    void (*free)(void*))
{
    OE_SpinLock(&_lock);
    _free_callback = free;
    void* ret = __OE_Tdelete(key, rootp, compar);
    _free_callback = (void*)0;
    OE_SpinUnlock(&_lock);

    return ret;
}

#define node __node
#define tdestroy __OE_Tdestroy

#include "../3rdparty/musl/musl/src/search/tdestroy.c"

void OE_Tdestroy(
    void *root, 
    void (*freekey)(void *nodep),
    void (*free)(void*))
{
    OE_SpinLock(&_lock);
    _free_callback = free;
    __OE_Tdestroy(root, freekey);
    _free_callback = (void*)0;
    OE_SpinUnlock(&_lock);
}

