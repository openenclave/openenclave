#include <stdio.h>
#include <assert.h>
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

