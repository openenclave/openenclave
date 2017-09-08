libc
====

This directory contains the scripts for the LIBC library, which is formed
from the following pieces:

    - Sources included from MUSL libc ([located here](../3rdparty/musl)
    - The dlmalloc heap allocator ([located here](../3rdparty/dlmalloc)
    - Additional source files to implement enclave-specific features.
    - Stubs to work around missing definitions needed by libunwind and libcxxrt

Enclave-specific features are defined in these files:

    - assert.c -- standard assert() for enclaves.
    - errno.c -- standard posix errno (located in the thread object)
    - pthread.c -- pthreads implementation based on enclave threads.
    - time.c -- time functions based on OCALLs.
    - link.c -- dl_iterate_phdr() (needed by libunwind)

