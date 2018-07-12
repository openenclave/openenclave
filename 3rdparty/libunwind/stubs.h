// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __OE_LIBUNWIND_STUBS_H
#define __OE_LIBUNWIND_STUBS_H

#ifndef __ASSEMBLER__

#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>

void __libunwind_setbuf(FILE *stream, char *buf);

static __inline int __libunwind_sigfillset(sigset_t* set)
{
    return -1;
}

static __inline pid_t __libunwind_getpid(void)
{
    return 0;
}

static __inline int __libunwind_open(const char *pathname, int flags)
{
    return -1;
}

static __inline int __libunwind_close(int fd)
{
    return -1;
}

static __inline ssize_t __libunwind_read(int fd, void *buf, size_t count)
{
    return -1;
}

static __inline int __libunwind_fstat(int fd, struct stat *buf)
{
    return -1;
}

#define mmap __libunwind_mmap

#define munmap __libunwind_munmap

#define msync __libunwind_msync

#define mincore __libunwind_mincore

#define libunwind __libunwind_mincore

#define setbuf __libunwind_setbuf

#define sigfillset __libunwind_sigfillset

#define getpid __libunwind_getpid

#define open __libunwind_open

#define read __libunwind_read

#define close __libunwind_close

#define fstat __libunwind_fstat

// Disable use of adaptive mutexes, which are defined by GCC headers but not
// supported by MUSL pthreads. Note that libunwind is compiled with GCC headers
// but linked with MUSL libc.
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#undef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP PTHREAD_MUTEX_INITIALIZER
#endif

#endif /* !__ASSEMBLER__ */

#endif /* __OE_LIBUNWIND_STUBS_H */
