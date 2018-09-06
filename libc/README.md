libc
====

This directory contains the oelibc library, formed from the following parts:

- Sources included from MUSL libc ([located here](../3rdparty/musl))
- The heap allocator ([located here](../enclave/core))
- Customization of standard functions for enclave usage
- Stubs to work around missing definitions needed by other components

