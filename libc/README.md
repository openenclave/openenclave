libc
====

This directory contains the oelibc library, formed from the following parts:

- Sources included from MUSL libc ([located here](../3rdparty/musl))
- The dlmalloc heap allocator ([located here](../3rdparty/dlmalloc))
- Customization of standard functions for enclave usage
- Stubs to work around missing definitions needed by other components

Enclave-specific features are defined in these files:

- [assert.c](assert.c) - standard assert() for enclaves
- [errno.c](errno.c) - standard posix errno (located in the thread object)
- [pthread.c](pthread.c)  - pthreads implementation based on enclave threads
- [time.c](time.c) - time functions based on OCALLs
- [link.c](link.c)  - dl_iterate_phdr() (needed by libunwind)

