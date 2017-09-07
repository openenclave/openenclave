#ifndef _OE_GALLOC_H
#define _OE_GALLOC_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

void* __OE_GMalloc(
    size_t size);

void __OE_GFree(
    void* ptr);

int __OE_GCheck(
    void* ptr);

size_t __OE_GCount(void);

bool __OE_GOwns(const void* ptr);

void __OE_GFix(void* ptr);

OE_EXTERNC_END

#endif /* _OE_GALLOC_H */
