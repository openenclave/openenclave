#ifndef _OE_HEAP_H
#define _OE_HEAP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

#define OE_PROT_NONE       0
#define OE_PROT_READ       1
#define OE_PROT_WRITE      2
#define OE_PROT_EXEC       4

#define OE_MAP_SHARED      1
#define OE_MAP_PRIVATE     2
#define OE_MAP_FIXED       16
#define OE_MAP_ANONYMOUS   32

#define OE_MAP_FAILED      ((void*)-1)

void* __OE_Sbrk(
    ptrdiff_t increment);

int __OE_Brk(
    uintptr_t addr);

int __OE_Madvise(
    void *addr, 
    size_t length, 
    int advice);

void *__OE_Mmap(
    void *addr, 
    size_t length, 
    int prot, 
    int flags,
    int fd, 
    off_t offset);

void *__OE_Mremap(
    void *old_address, 
    size_t old_size,
    size_t new_size, 
    int flags, 
    ... /* void *new_address */);

int __OE_Munmap(
    void *addr, 
    size_t length);

#endif /* _OE_HEAP_H */
