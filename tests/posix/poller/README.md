poller test:
============

This test excercises the select function. It defines client.c and server.c
and runs them in the following combinations:

    - host-to-host
    - host-to-enclave
    - enclave-to-host
    - enclave-to-enclave

The host creates N client threads that run against a single server. The server
utilizes non-blocking socket I/O and tests the EAGAIN condition.
