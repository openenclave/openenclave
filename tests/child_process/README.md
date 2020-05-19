This directory tests if a parent process' enclave can be called or destroyed from a child process, or if a new enclave can be create from a child process. It does so by having a host app create an enclave, fork itself and then invoke the following from the child process:
1. tests/child_process_ecall tries to make an ECall into an enclave from the child process.
2. tests/child_process_destroy tries to destroy the enclave from the child process.
3. tests/child_process_create tries to create a new enclave from the child process.
