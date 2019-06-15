sendmsg test:
=============

This test excercises sendmsg() and recvmsg(). It defines client.c and server.c
and runs them in the following combinations:

    - host-to-host
    - host-to-enclave
    - enclave-to-host
    - enclave-to-enclave

This tests whether the client.c and server.c can be compiled and run on both
the host and enclave sides.

This test defines two enclaves for running the client or server:

    - enc1 - compiles and links with libc (MUSL).
    - enc2 - compiles and links with corelibc (MUSL).

This tests whether the client.c and server.c enclaves will build and run
against both libc and corelibc.
