// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __OE_LIBUNWIND_STUBS_H
#define __OE_LIBUNWIND_STUBS_H

#ifndef __ASSEMBLER__

#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

void __libunwind_setbuf(FILE *stream, char *buf);

#define mmap __libunwind_mmap

#define munmap __libunwind_munmap

#define msync __libunwind_msync

#define mincore __libunwind_mincore

#define libunwind __libunwind_mincore

#define setbuf __libunwind_setbuf

// Disable use of adaptive mutexes, which are defined by GCC headers but not
// supported by MUSL pthreads. Note that libunwind is compiled with GCC headers
// but linked with MUSL libc.
#ifdef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#undef PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP
#define PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP PTHREAD_MUTEX_INITIALIZER
#endif

#endif /* !__ASSEMBLER__ */

#endif /* __OE_LIBUNWIND_STUBS_H */
