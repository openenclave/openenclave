libc
====

This directory contains the oelibc library, formed from the following parts:

- Sources included from MUSL libc ([located here](../3rdparty/musl))
- The dlmalloc heap allocator ([located here](../3rdparty/dlmalloc))
- Customization of standard functions for enclave usage
- Stubs to work around missing definitions needed by other components

Enclave-specific features are defined in these files:

- [arc4random.c](arc4random.c)  - arc4random() function.
- [libcxxrt_stubs.c](libcxxrt_stubs.c)  - stubs needed by libcxxrt.
- [libunwind_stubs.c](libunwind_stubs.c)  - stubs needed by libunwind.
- [malloc.c](malloc.c)  - malloc implementation based on dlmalloc.
- [pthread.c](pthread.c)  - pthreads implementation based on enclave threads.
- [sched_yield.c](sched_yield.c)  - sched_yield_yield() panic stub.
- [strerror.c](strerror.c)  - strerror() function.
- [syscalls.c](syscalls.c)  - syscalls for musl libc.
- [time.c](time.c)  - POSIX time functions.
- [musl_stubs.c](musl_stubs.c)  - stubs needed by musl libc.
- [sysconf.c](sysconf.c)  - sysconf() function.

wait.c
