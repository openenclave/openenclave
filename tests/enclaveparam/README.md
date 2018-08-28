gethostenclave:
===============

This function tests the new optional **enclave** OCALL parameter.

The host creates three instances of the same enclave and then initiates
the following sequence of calls.

    - enclave-1:test_enclave_param()
    - host:callback_1
    - enclave-2:test_enclave_param()
    - host:callback_2
    - enclave-3:test_enclave_param()
    - host:callback_3

