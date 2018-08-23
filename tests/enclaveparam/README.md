gethostenclave:
===============

This function tests the **oe_get_host_enclave()** function, which retrieves the
instance of the enclave that invoked the current OCALL.

The host creates three instances of the same enclave and then initiates
the following sequence of calls.

    - enclave-1:test_get_host_enclave()
    - host:callback_1
    - enclave-2:test_get_host_enclave()
    - host:callback_2
    - enclave-3:test_get_host_enclave()
    - host:callback_3

