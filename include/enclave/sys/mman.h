#ifndef __ELIBC_SYS_MMAN_H
#define __ELIBC_SYS_MMAN_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#define PROT_NONE       0
#define PROT_READ       1
#define PROT_WRITE      2
#define PROT_EXEC       4

#define MAP_SHARED      1
#define MAP_PRIVATE     2
#define MAP_FIXED       16

#define MAP_ANONYMOUS   32

#define MAP_FAILED      ((void*)-1)

#ifdef __ELIBC_UNSUPPORTED
void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
#endif

#ifdef __ELIBC_UNSUPPORTED
int munmap(void *addr, size_t length);
#endif

#ifdef __ELIBC_UNSUPPORTED
int mprotect(void *addr, size_t len, int prot);
#endif

#ifdef __ELIBC_UNSUPPORTED
int msync(void *addr, size_t length, int flags);
#endif

#ifdef __ELIBC_UNSUPPORTED
int mincore(void *addr, size_t length, unsigned char *vec);
#endif

__ELIBC_END

#endif /* __ELIBC_SYS_MMAN_H */
