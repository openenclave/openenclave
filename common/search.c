#include <openenclave/bits/search.h>

#ifdef OE_BUILD_UNTRUSTED
# include <search.h>
#endif

void *__OE_tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *));

void __OE_tdestroy(
    void *root, 
    void (*freekey)(void *nodep));

void *__OE_tdelete(
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
#define tdelete __OE_tdelete
#define tfind OE_tfind
#define tsearch __OE_tsearch
#define twalk OE_twalk

/* Redirect to call user-provided free and malloc */
#define free _OE_free
#define malloc _OE_malloc

static void* (*_malloc_callback)(size_t size);

static void* _OE_malloc(size_t size)
{
    if (_malloc_callback)
        return (*_malloc_callback)(size);

    return (void*)0;
}

static void (*_free_callback)(void* ptr);

static void _OE_free(void* ptr)
{
    if (_free_callback)
        (*_free_callback)(ptr);
}

#include "../3rdparty/musl/musl/src/search/tsearch_avl.c"

void *OE_tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *),
    void* (*malloc)(size_t))
{
    _malloc_callback = malloc;
    void* ret = __OE_tsearch(key, rootp, compar);
    _malloc_callback = (void*)0;

    return ret;
}

void *OE_tdelete(
    const void *restrict key, 
    void **restrict rootp,
    int(*compar)(const void *, const void *),
    void (*free)(void*))
{
    _free_callback = free;
    void* ret = __OE_tdelete(key, rootp, compar);
    _free_callback = (void*)0;

    return ret;
}

#define node __node
#define tdestroy __OE_tdestroy

#include "../3rdparty/musl/musl/src/search/tdestroy.c"

void OE_tdestroy(
    void *root, 
    void (*freekey)(void *nodep),
    void (*free)(void*))
{
    _free_callback = free;
    __OE_tdestroy(root, freekey);
    _free_callback = (void*)0;
}

