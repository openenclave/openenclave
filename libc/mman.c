#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/heap.h>

void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
    if (fd != -1 || off != 0)
    {
        assert("__mmap(): panic" == NULL);
        return (void*)-1;
    }

    return OE_Map(start, len, prot, flags);
}

int __madvise(void* addr, size_t len, int advice)
{
    /* Do nothing */
    return 0;
}

void* __mremap(void* old_addr, size_t old_len, size_t new_len, int flags, ...)
{
    return OE_Remap(old_addr, old_len, new_len, flags);
}

int __munmap(void *start, size_t len)
{
    OE_Result result = OE_Unmap(start, len);

    return result == OE_OK ? 0 : -1;
}

uintptr_t __brk(uintptr_t newbrk)
{
    if (newbrk == 0)
        return (uintptr_t)OE_Sbrk(0);

    if (OE_Brk(newbrk) != 0)
        return (uintptr_t)((void*)-1);

    return newbrk;
}

int brk(void* addr)
{
    return OE_Brk((uintptr_t)addr);
}

void* sbrk(ptrdiff_t increment)
{
    return OE_Sbrk(increment);
}

void* mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
    return __mmap(start, len, prot, flags, fd, off);
}

int madvise(void* addr, size_t len, int advice)
{
    return __madvise(addr, len, advice);
}

void* mremap(void* old_addr, size_t old_len, size_t new_len, int flags, ...)
{
    return __mremap(old_addr, old_len, new_len, flags);
}

int munmap(void *start, size_t len)
{
    return __munmap(start, len);
}

int msync(void* addr, size_t length, int flags)
{
    /* Nothing to do */
    return 0;
}

int mincore(void *addr, size_t length, unsigned char *vec)
{
    if (!addr || !vec)
        return -1;

    size_t n = (length + OE_PAGE_SIZE - 1) / OE_PAGE_SIZE;
    memset(vec, 1, n);

    return 0;
}

