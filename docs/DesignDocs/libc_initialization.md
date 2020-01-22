# Musl libc Initialization

## Normal musl libc initialization on Linux x86\_64

A normal executable linux program which uses Musl libc will have the following initialization pattern,
where `_start()` is the entry point of every program.


```
_start()
    v
    |
    --> _start_c()
              v
              |
              --> _libc_start_main()
                            v
                            |
                            --> __init_libc()
                            --> _libc_start_main_stage2()
                                          v
                                          |
                                          --> __libc_start_init()
                                          --> main()
                                          --> exit()
```

### What do each of these functions do?
#### \_start

`_start` is the entry point for every userspace executable. Its only
purpose is to initialize rbp to 0 and call `_start_c`.

#### \_start\_c

Sets some registers and calls `_libc_start_main`

#### \_libc\_start\_main

Calls `__init_libc` and `_libc_start_main_stage2`

#### \_\_init\_libc

Finally something interesting. `__init_libc` does many things:

* Calls `__init_tls()` to initialize thread local storage
* Calls `__init_ssp()` to initialize stack protector
* Calls poll syscall to check if stdin, stdout, and stderr to be ready for I/O. If any are not available for I/O, it initializes them to /dev/null
* sets the following global variables:
    * `__environ`
    * `__hwcap`
    * `__sysinfo`
    * `__progname`
* Sets the following members of the global `libc` structure
    * `auxv`
    * `page_size`
    * `secure`

#### \_libc\_start\_main\_stage2

Calls `__libc_start_init()`. Then calls `main()`. Then calls `exit()` with the return
code of `main()`.

#### \_\_libc\_start\_init:

Calls `_init()` and loops through `__init_array()` and calls each of the
compiler-generated init functions.

This includes constructors of C++ global objects and functions marked with the
constructor attribute.

## OE Initialization

### OE libc Initialization

OE initializes libc in similar ways, but leaves out some of the initialization
that is not needed in the enclave. Additional musl-specific initialization is
done by a function `_oe_init_c()` which is marked with the constructor attribute.
This ensures that enclaves which link libc will call `_oe_init_c()` during
`oe_call_init_functions()`.

#### \_\_init\_tls

OE initializes thread local storage via a call to `oe_thread_local_init()` in
enclave/core/linux/threadlocal.c which is called during `td_init()` which
initializes a thread data structure.

#### \_\_init\_ssp

`td_init()` is also responsible for initializing the stack protector.

#### Check for availability of stdin, stdout, and stderr

OE enclaves do console I/O by making ocalls to the host. Because of this,
the job of checking console I/O file descriptors is handled by the host's
libc implementation.

#### Initialize global variables

* `__environ`

    `__environ` is a pointer to the `envp` argument that can be passed to `main()`, which
    contains the current environment variables. Because the enclave does not inherit an
    initial set of environment variables, this is not initialized. Environment-based libc
    functions such as `putenv`, `getenv`, etc. will still work as expected. No musl functions
    assume __environ is non-null.

* `__hwcap`

    `__hwcap` is a bitmask of flags detailing whether various features are supported
    by the system's CPU. In general, hwcaps are used by the kernel, but musl uses
    a few of them for threading. It checks for `CPU_HAS_CAS_L`, `CPU_HAS_LLSC`, and
    `HWCAP_TLS`.

    Each of these are used for thread local storage. Because OE implements its own
    TLS, these flags do not need to be initialized.

* `__sysinfo`

    On x86_64 this is not used by musl. OE does not need to initialize.

* `__progname`

    `__progname` contains the name of the executing program (`argv[0]`). It is used by
    musl libc in `warn()` and `err()` functions to print a message to stderr prefixed by the
    program name. Musl initializes `__progname` to null, so these calls will succeed and
    simply have an empty prefix.

    OE does not need to initialize this value explicitly.

#### Initialize members of the libc struct

Musl libc maintains a libc struct which tracks some global configurations. `__init_libc()`
initializes some of these members.

* `auxv`

    This is a pointer to the part of the auxilary vector that is not used for argc, argv,
    and envp. In general, the auxillary vector is a mechanism for the kernel's loader
    to pass information to a userspace program when it is executed. Musl libc uses the
    auxillary vector for the following:

    * Thread local storage
    * Dynamic loading of shared objects.
    * The `getauxval` call used for reading from the auxilary vector by userspace program.

    OE initializes auxv as an array containing 1 zero entry. This denotes an empty vector.

* `page_size`

    Musl libc uses `page_size` for dynamic linking, pthreads, memory allocation, and the
    sysconf call.

    In order to support calls to sysconf, OE initializes `page_size` to `OE_PAGE_SIZE`
    which is 4096 by default.

* `secure`

    If the secure flag is non-zero, musl libc disables some potentially unsafe operations.
    This includes using the environment for locale/timezone information and dynamic loading
    paths.

    OE should not implicitly take input from the environment, so this value is initialized
    to 1.

#### \_\_init\_array functions

OE calls all functions in the `init_array` section during
`oe_call_init_functions()` on enclave load. libc initialization is added as an
Open Enclave Module initialization function to ensure it is called prior to these
initialization functions.

## References:
[1] System V ABI: https://www.uclibc.org/docs/psABI-x86\_64.pdf

[2] Musl libc source: https://git.musl-libc.org/cgit/musl
