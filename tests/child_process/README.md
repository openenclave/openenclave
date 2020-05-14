**Note:** This test is currently disabled. Version 1.33 of the SGX DCAP driver
introduces support accessing an enclave from a forked child process. This causes
this test to fail when using that driver. Version 1.22 does not have fork support
so this test will pass.

Ultimately when older versions of the DCAP driver are deprecated, this test should
be re-enabled and modified to check that ecalls/terminate SUCCEEDS from a forked
child.


This directory tests that a parent process' enclave cannot be called or destroyed from a child process. It does so by having a host app create an enclave, fork itself and then invoke the following from the child process:
1. tests/child_process_ecall tries to make an ECall into an enclave from the child process.
2. tests/child_process_destroy tries to destroy the enclave from the child process. 
