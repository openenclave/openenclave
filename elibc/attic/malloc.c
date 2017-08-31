#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openenclave.h>
#include <oeinternal/globals.h>

#define _PTHREAD_IMPL_H
#define __wait(...)
#define __wake(...)
#define MREMAP_MAYMOVE 0
#define MADV_DONTNEED 0
#define PAGE_SIZE 4096

uintptr_t __brk(uintptr_t addr);

static void *__mmap(
    void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void* result = MAP_FAILED;

    if (addr || fd != -1 || offset)
        goto done;

    if (prot != (PROT_READ | PROT_WRITE))
        goto done;

    if (flags != (MAP_PRIVATE | MAP_ANONYMOUS))
        goto done;

    /* Round size to next multiple of size */
    length = (length + PAGE_SIZE - 1) / PAGE_SIZE  * PAGE_SIZE;

    result = sbrk(length);

done: 

    assert(result != NULL);
    return result;
}

static int __madvise(void *addr, size_t length, int advice)
{
    /* Nothing to do */
    return 0;
}


static int __munmap(void *addr, size_t length)
{
    if (!addr)
        return -1;

    /* Nothing to do */

    return 0;
}

#include "../3rdparty/musl/musl/src/malloc/malloc.c"
