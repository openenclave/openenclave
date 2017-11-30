#include <openenclave/enclave.h>
#include <openenclave/bits/heap.h>
#include <assert.h>

void* __mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
    if (fd != -1 || off != 0)
    {
        assert("__mmap(): panic" == NULL);
        return (void*)-1;
    }

    void* ptr = OE_Map(start, len, prot, flags);

    if (!ptr)
        return (void*)-1;

    return ptr;
}

int __madvise(void* addr, size_t len, int advice)
{
    /* Do nothing */
    return 0;
}

void* __mremap(void* old_addr, size_t old_len, size_t new_len, int flags, ...)
{
    return NULL;
}

int __munmap(void *start, size_t len)
{
    return 0;
}

uintptr_t __brk(uintptr_t newbrk)
{
    return 0;
}
