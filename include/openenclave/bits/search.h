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

struct OE_tnode 
{
    void *key;                  /* pointer to this struture */
    struct OE_tnode *left;      /* pointer to left child */
    struct OE_tnode *right;     /* pointer to right child */
    int height;                 /* height of this subtree */
    int padding;                /* Pad struct out to exactly 32 bytes */
};

OE_STATIC_ASSERT(sizeof(struct OE_tnode) == 32);

void *OE_tsearch(
    const void *key, 
    void **rootp,
    int (*compar)(const void *, const void *),
    void* (*malloc)(size_t));

void *OE_tfind(
    const void *key, 
    void *const *rootp,
    int(*compar)(const void *, const void *));

void *OE_tdelete(
    const void *restrict key, 
    void **restrict rootp,
    int(*compar)(const void *, const void *),
    void (*free)(void*));

void OE_twalk(
    const void *root, 
    void (*action)(const void *, OE_VISIT, int));

void OE_tdestroy(
    void *root, 
    void (*freekey)(void *nodep),
    void (*free)(void*));

#endif /* _OE_SEARCH_H */
