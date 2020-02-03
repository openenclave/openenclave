core
====

This directory contains the sources for the oecore library, which implements
the enclave intrinsics. The main parts include:

- Enclave entry ([main.S](main.S)) and exit ([exit.S](exit.S)) functions

- Enclave initialization ([init.c](init.c))

- ECALL and OCALL dispatching logic ([calls.c](calls.c))

- The thread data (TD) structure ([td.c](td.c))

- Spinlock implementation ([spinlock.c](spinlock.c))

- Enclave threads implementation ([thread.c](thread.c))

- Functions for testing enclave memory boundaries ([memory.c](memory.c))

- Globals set during enclave signing and loading ([globals.c](globals.c))

- Host calls ([hostcalls.c](hostcalls.c))

- Standard-like string functions ([string.c](string.c))

- Assertion implementation ([assert.c](assert.c))

- Enclave setjmp and longjmp functions ([jump.c](jump.c))

- Functions for report creation (ENCLU.EREPORT) ([report.c](report.c))

- Enclave sbrk() implementation ([sbrk.c](sbrk.c))

- Entropy ([random.c](random.c)
