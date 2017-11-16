/*
**==============================================================================
**
** search.h
**
**     This header defines tree functions that have similar signatures to the
**     ones found in the standard POSIX <search.h> header. There are two
**     differences:
**
**         (1) Each definition bears the "OE_" prefix.
**         (2) Some functions take additional malloc/free callback arguments.
**
**     The second difference allows callers to control the memory management 
**     policy. Note that the original implementation directly calls malloc and 
**     free.
**
**     The implementation (see openenclave/common/search.c) defines wrappers
**     around the standard functions defined by the C library.
**
**     Note that these functions are not thread safe and locks should be used
**     when invoking them.
**
**==============================================================================
*/

#ifndef _OE_SEARCH_H
#define _OE_SEARCH_H

#include <openenclave/defs.h>

typedef unsigned long size_t;

typedef enum 
{ 
    OE_preorder, 
    OE_postorder, 
    OE_endorder, 
    OE_leaf 
} 
OE_VISIT;

struct OE_Tnode 
{
    void *key;                  /* pointer to this struture */
    struct OE_Tnode *left;      /* pointer to left child */
    struct OE_Tnode *right;     /* pointer to right child */
    int height;                 /* height of this subtree */
    int padding;                /* Pad struct out to exactly 32 bytes */
};

OE_STATIC_ASSERT(sizeof(struct OE_Tnode) == 32);

void *OE_Tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *),
    void* (*alloc)(size_t, void* data),
    void* data);

void *OE_Tfind(
    const void *key, 
    void *const *rootp,
    int(*compar)(const void *, const void *));

void *OE_Tdelete(
    const void *restrict key, 
    void **restrict rootp,
    int(*compar)(const void *, const void *),
    void (*free)(void*));

void OE_Twalk(
    const void *root, 
    void (*action)(const void *, OE_VISIT, int));

void OE_Tdestroy(
    void *root, 
    void (*freekey)(void *nodep),
    void (*free)(void*));

#endif /* _OE_SEARCH_H */
