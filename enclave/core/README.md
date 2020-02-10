core
====

This directory contains the sources for the oecore library, which implements
the enclave intrinsics. The main parts include:

- Enclave entry ([sgx/enter.S](sgx/enter.S)) and exit ([sgx/exit.S](sgx/exit.S)) functions

- Enclave initialization ([sgx/init.c](sgx/init.c))

- ECALL and OCALL dispatching logic ([calls.c](calls.c))

- The thread data (TD) structure ([sgx/td.c](sgx/td.c))

- Spinlock implementation ([sgx/spinlock.c](sgx/spinlock.c) and [optee/spinlock.c](optee/spinlock.c))

- Enclave threads implementation ([sgx/thread.c](sgx/thread.c) and [optee/thread.c](sgx/thread.c))

- Functions for testing enclave memory boundaries ([sgx/memory.c](sgx/memory.c))

- Globals set during enclave signing and loading ([sgx/globals.c](sgx/globals.c) and [optee/globals](optee/globals.c))

- Host calls ([sgx/hostcalls.c](sgx/hostcalls.c) and [optee/hostcalls.c](optee/hostcalls.c))

- Standard-like string functions ([string.c](string.c))

- Assertion implementation ([assert.c](assert.c))

- Enclave setjmp and longjmp functions ([sgx/longjmp.S](sgx/longjmp.S) and [sgx/setjmp.S](sgx/setjmp.S))

- Enclave sbrk() implementation ([sbrk.c](sbrk.c))

- Entropy ([random.c](random.c))
