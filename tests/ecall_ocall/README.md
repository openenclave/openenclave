ECall/Ocall tests
=================

Testing various functionality around ecalls/ocalls:
- verify OCall can be executed in global initializers
- verify non-exported enclave functions cannot be called
- verify threads are actually executed in parallel (not round-robin nested on ocall)
  + multi-thread in enclave
  + multi-enclave / multi-thread

