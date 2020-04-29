// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef __OE_LIBUNWIND_STUBS_H
#define __OE_LIBUNWIND_STUBS_H

#if !defined(__ASSEMBLER__)

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// Disable use of adaptive mutexes, which are defined by GCC headers but not
// supported by MUSL pthreads. Note that libunwind is compiled with GCC headers
// but linked with MUSL libc.
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#undef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP PTHREAD_MUTEX_INITIALIZER
#endif

/* Redirect these calls to the stubs defined below */
#define setbuf __libunwind_setbuf
#define sigfillset __libunwind_sigfillset
#define getpid __libunwind_getpid
#define open __libunwind_open
#define read __libunwind_read
#define close __libunwind_close
#define fstat __libunwind_fstat
#define mmap __libunwind_mmap
#define munmap __libunwind_munmap
#define msync __libunwind_msync
#define mincore __libunwind_mincore
#define pipe2 __libunwind_pipe2
#define syscall __libunwind_syscall

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wsign-conversion"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

static __inline void __libunwind_setbuf(FILE* stream, char* buf)
{
}

static __inline int __libunwind_sigfillset(sigset_t* set)
{
    return -1;
}

static __inline pid_t __libunwind_getpid(void)
{
    return 0;
}

static __inline int __libunwind_open(const char* pathname, int flags)
{
    return -1;
}

static __inline ssize_t __libunwind_read(int fd, void* buf, size_t count)
{
    return -1;
}

static __inline int __libunwind_close(int fd)
{
    return -1;
}

static __inline int __libunwind_fstat(int fd, struct stat* buf)
{
    return -1;
}

static __inline void* __libunwind_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    void* oe_nodebug_memalign(size_t alignment, size_t size);
    void* result = MAP_FAILED;

    if (addr || fd != -1 || offset)
        goto done;

    if (prot != (PROT_READ | PROT_WRITE))
        goto done;

    if (flags != (MAP_PRIVATE | MAP_ANONYMOUS))
        goto done;

    result = oe_nodebug_memalign(4096, length);

done:

    return result;
}

static __inline int __libunwind_munmap(void* addr, size_t length)
{
    extern void oe_nodebug_free(void* ptr);

    if (!addr)
        return -1;

    if (length)
        oe_nodebug_free(addr);

    return 0;
}

static __inline int __libunwind_msync(void* addr, size_t length, int flags)
{
    return 0;
}

static __inline int __libunwind_mincore(
    void* addr,
    size_t length,
    unsigned char* vec)
{
    if (!addr || !vec)
        return -1;

    size_t n = (length + getpagesize() - 1) / getpagesize();
    memset(vec, 1, n);

    return 0;
}

static __inline int __libunwind_pipe2(int pipefd[2], int flags)
{
    return -1;
}

static __inline long __libunwind_syscall(long number, ...)
{
    return 0;
}

#endif /* !defined(__ASSEMBLER__) */

#endif /* __OE_LIBUNWIND_STUBS_H */
