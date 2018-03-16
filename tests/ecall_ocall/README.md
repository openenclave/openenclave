ECall/Ocall tests
=================

Testing various functionality around ecalls/ocalls:
- verify OCall can be executed in global initializers
- verify non-exported enclave functions cannot be called
- verify threads are actually executed in parallel (not round-robin nested on ocall)
  + multi-thread in enclave
  + multi-enclave / multi-thread
- recursive Ecall/Ocall: Functions are called properly, with right arguments on right threads,
  preserving stack-state
  + single-threaded
  + multi-threaded
  + multi-enclave / multi-threaded

